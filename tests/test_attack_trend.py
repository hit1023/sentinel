import datetime
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webui"))


class Trend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_trend", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()

    def test_daily_and_weekly(self):
        m = self.m
        now = time.time()
        with m._db_connect() as c:
            def add(ep, cat):
                c.execute("INSERT INTO alerts (epoch, host, category, severity, message) VALUES (?,?,?,?,?)",
                          (ep, "h", cat, "WARNING", "x"))
            for d in (0, 0, 0, 1, 40):  # 40日前は日毎(30日)の範囲外
                add(now - d * 86400, "auth_watch")
            add(now, "web_watch")
            add(now, "outbound_watch")  # OUTは攻撃件数に含めない
            c.execute("INSERT INTO auto_blocks (ip, blocked_at, score, events, dry_run, reason) VALUES ('8.8.8.8', ?, 100, 3, 0, 'reputation')", (now,))
            c.execute("INSERT INTO auto_blocks (ip, blocked_at, score, events, dry_run, reason) VALUES ('9.9.9.9', ?, 100, 3, 1, 'reputation')", (now,))  # 試験は数えない
        r = m.api_attack_trend()
        d, w = r["daily"], r["weekly"]
        self.assertEqual((len(d), len(w)), (30, 12))
        today = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).date()
        self.assertEqual(d[-1], {"date": today.isoformat(), "ssh": 3, "web": 1, "blocked": 1})
        self.assertEqual(d[-2]["ssh"], 1)
        self.assertEqual(sum(x["ssh"] for x in d), 4)
        self.assertEqual(sum(x["blocked"] for x in d), 1)
        monday = today - datetime.timedelta(days=today.weekday())
        self.assertEqual(w[-1]["date"], monday.isoformat())  # 週は月曜始まり
        self.assertEqual(sum(x["web"] for x in w), 1)
        self.assertEqual(sum(x["blocked"] for x in w), 1)

    def test_range_is_clamped(self):
        r = self.m.api_attack_trend(days=9999, weeks=0)
        self.assertEqual((len(r["daily"]), len(r["weekly"])), (90, 4))


if __name__ == "__main__":
    unittest.main()
