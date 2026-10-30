import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webui"))
import abuseipdb


class AutoReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_autoreport", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        cls.alerts = []
        cls.m._emit_internal_alert = lambda *a, **k: cls.alerts.append(a)
        cls.reports = []
        cls.scores = {"8.8.8.8": 100, "9.9.9.9": 47, "4.4.4.4": 100, "5.5.5.5": 100}

        def fake_request(path, key, data=None, timeout=15):
            if "/check" in path:
                ip = path.split("ipAddress=")[1].split("&")[0]
                return {"data": {"abuseConfidenceScore": cls.scores.get(ip, 0), "totalReports": 50}}, {}
            cls.reports.append(data["ip"])
            return {"data": {"abuseConfidenceScore": 100}}, {}
        abuseipdb._request = fake_request
        cls.m.attack_map._geo = lambda ips: {i: {"lat": 1, "lon": 1, "country": "T", "country_code": "TT", "city": ""} for i in ips}
        cls.m.publicfeed.lookup_asn = lambda c, ips: {i: {"asn": "AS1", "name": "N", "org": "x"} for i in ips}
        cls.m._set_app_setting("abuseipdb_api_key", "k" * 40)
        cls.m._set_app_setting("auto_block_mode", "off")

    def setUp(self):
        # テスト同士が影響しないよう、毎回まっさらにする
        with self.m._db_connect() as c:
            for t in ("alerts", "abuse_reports", "known_good_ips", "abuse_rep_cache", "auto_blocks"):
                c.execute(f"DELETE FROM {t}")
        self.reports.clear()
        self.alerts.clear()
        self.m._set_app_setting("abuseipdb_auto_report", "on")
        self.m._set_app_setting("abuseipdb_auto_report_score", "100")

    def attack(self, ip, n):
        now = time.time()
        for i in range(n):
            self.m._persist_important({"id": f"{ip}-{i}-{now}", "epoch": now - 60 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                       "severity": "warning", "message": f"SSHログイン失敗: user=root from={ip} port=22"})

    def test_only_high_score_safe_ips_are_reported_once(self):
        m = self.m
        for ip, n in (("8.8.8.8", 6), ("9.9.9.9", 6), ("4.4.4.4", 6), ("1.2.3.4", 2), ("192.168.0.9", 9)):
            self.attack(ip, n)
        m._note_login_success({"category": "auth_watch", "severity": "info", "message": "ログイン成功: user=hit from=4.4.4.4 method=publickey"})
        r = m._abuse_auto_report_run()
        self.assertEqual([x["ip"] for x in r["reported"]], ["8.8.8.8"])  # 信頼度100%だけ。47%・回数不足・LAN・自分のIPは除く
        self.assertEqual(self.reports, ["8.8.8.8"])
        self.assertIn("自動通報", self.alerts[-1][1])
        self.assertNotIn("8.8.8.8", self.alerts[-1][1])                  # 通知にはIPを伏せて載せる
        self.assertEqual(m._abuse_auto_report_run()["reported"], [])     # 同じIPを繰り返さない
        self.assertEqual(self.reports, ["8.8.8.8"])

    def test_off_and_threshold_settings(self):
        m = self.m
        self.attack("5.5.5.5", 6)
        m._set_app_setting("abuseipdb_auto_report", "off")
        self.assertEqual(m._abuse_auto_report_run()["reported"], [])
        self.assertNotIn("5.5.5.5", self.reports)
        self.assertEqual(m._auto_report_settings(), (False, 100))
        m._set_app_setting("abuseipdb_auto_report", "on")
        m._set_app_setting("abuseipdb_auto_report_score", "30")           # 下限75に丸める
        self.assertEqual(m._auto_report_settings(), (True, 75))
        self.assertEqual([x["ip"] for x in m._abuse_auto_report_run()["reported"]], ["5.5.5.5"])
        m._set_app_setting("abuseipdb_auto_report_score", "100")

    def test_daily_reserve_for_manual_reports(self):
        m = self.m
        with m._db_connect() as c:
            for i in range(abuseipdb.MAX_REPORTS_PER_DAY - m.AUTO_REPORT_RESERVE):
                c.execute("INSERT INTO abuse_reports (ip, reported_at, categories, event_count, score) VALUES (?, ?, '18', 5, 100)", (f"10.9.{i}.1", time.time()))
        self.scores["7.7.7.7"] = 100
        self.attack("7.7.7.7", 6)
        self.assertEqual(m._abuse_auto_report_run()["reported"], [])      # 手動用の枠は残す
        self.assertNotIn("7.7.7.7", self.reports)


if __name__ == "__main__":
    unittest.main()
