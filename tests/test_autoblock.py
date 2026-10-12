import asyncio
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webui"))
import abuseipdb
import autoblock


class Pure(unittest.TestCase):
    def test_whitelist_and_targets(self):
        self.assertTrue(autoblock.in_whitelist("203.0.113.5", ["日本", "203.0.113.0/24"]))
        self.assertFalse(autoblock.in_whitelist("198.51.100.5", ["日本", "203.0.113.0/24"]))
        t = autoblock.pick_targets({"8.8.8.8": 9, "192.168.0.5": 50, "9.9.9.9": 2, "1.1.1.1": 7, "4.4.4.4": 6, "5.5.5.5": 5},
                                   min_events=3, whitelist=["1.1.1.1"], known_good={"4.4.4.4"}, already={"5.5.5.5"}, limit=10)
        self.assertEqual(t, ["8.8.8.8"])  # LAN・回数不足・許可リスト・自分が使うIP・ブロック済みは除く

    def test_line_and_mask(self):
        import datetime
        jst = datetime.timezone(datetime.timedelta(hours=9))
        line = autoblock.ban_line("8.8.8.8", 100, 7, 1_800_000_000.0, jst)
        self.assertRegex(line, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+0900 SENTINEL-BAN 8\.8\.8\.8 score=100 events=7\n$")
        self.assertEqual(autoblock.mask("8.8.8.8"), "8.8.8.x")


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        os.environ["IDS_DATA_DIR"] = cls.dir
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_ab", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        cls.m._emit_internal_alert = lambda *a, **k: cls.alerts.append(a)
        cls.alerts = []
        scores = {"8.8.8.8": 100, "9.9.9.9": 40, "4.4.4.4": 100, "7.7.7.7": 5}
        abuseipdb._request = lambda path, key, data=None, timeout=15: (
            ({"data": {"abuseConfidenceScore": scores.get(path.split("ipAddress=")[1].split("&")[0], 0), "totalReports": 50}}, {})
            if "/check" in path else ({"data": {"abuseConfidenceScore": 100}}, {}))
        cls.m.attack_map._geo = lambda ips: {i: {"lat": 1, "lon": 1, "country": "T", "country_code": "TT", "city": ""} for i in ips}
        cls.m.publicfeed.lookup_asn = lambda c, ips: {i: {"asn": "AS1", "name": "N", "org": "x"} for i in ips}

    def add_attacks(self, ip, n):
        now = time.time()
        for i in range(n):
            self.m._persist_important({"id": f"{ip}-{i}-{now}", "epoch": now - 60 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                       "severity": "warning", "message": f"SSHログイン失敗: user=root from={ip} port=22"})

    def test_modes_and_safety(self):
        m = self.m
        m._set_app_setting("abuseipdb_api_key", "k" * 40)
        for ip, n in (("8.8.8.8", 6), ("9.9.9.9", 6), ("4.4.4.4", 6), ("7.7.7.7", 2), ("192.168.0.9", 9)):
            self.add_attacks(ip, n)
        m._set_app_setting("auto_block_mode", "off")
        self.assertEqual(m._auto_block_run()["blocked"], [])
        # 4.4.4.4は普通にログインに成功したことのあるIP（INFO）→対象外
        m._persist_important  # noqa
        rec = {"category": "auth_watch", "severity": "info", "message": "ログイン成功: user=hit from=4.4.4.4 method=publickey"}
        m._note_login_success(rec)
        # 不審なログイン成功（CRITICAL）の相手は「自分のIP」として覚えない
        m._note_login_success({"category": "auth_watch", "severity": "critical", "message": "ログイン成功: user=hit from=7.7.7.7 見慣れない国"})
        with m._db_connect() as c:
            self.assertEqual([r["ip"] for r in c.execute("SELECT ip FROM known_good_ips")], ["4.4.4.4"])
        m._set_app_setting("auto_block_mode", "dryrun")
        r = m._auto_block_run()
        self.assertEqual([b["ip"] for b in r["blocked"]], ["8.8.8.8"])      # 信頼度100%＋攻撃6回だけ。40%・回数不足・LAN・既知は除く
        self.assertFalse(os.path.exists(m.AUTO_BLOCK_FILE))                  # 試験では書かない
        self.assertIn("試験", self.alerts[-1][1])
        self.assertEqual(m._auto_block_run()["blocked"], [])                 # 同じIPを繰り返さない
        m._set_app_setting("auto_block_mode", "on")                          # 試験の記録は、本番への切替を妨げない
        r = m._auto_block_run()
        self.assertEqual([b["ip"] for b in r["blocked"]], ["8.8.8.8"])
        text = open(m.AUTO_BLOCK_FILE).read()
        self.assertIn("SENTINEL-BAN 8.8.8.8 score=100 events=6", text)
        self.assertNotIn("9.9.9.9", text)
        self.assertNotIn("試験", self.alerts[-1][1])

    def test_reported_ip_is_blocked_on_report_and_on_return(self):
        m = self.m
        m._set_app_setting("abuseipdb_api_key", "k" * 40)
        m._set_app_setting("auto_block_mode", "on")
        self.add_attacks("6.6.6.6", 6)
        r = asyncio.run(m.api_abuse_report({"ip": "6.6.6.6"}))
        self.assertTrue(r["blocked"])
        self.assertIn("SENTINEL-BAN 6.6.6.6", open(m.AUTO_BLOCK_FILE).read())


if __name__ == "__main__":
    unittest.main()
