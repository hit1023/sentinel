import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webui"))
import abuseipdb

SCORES = {"8.8.8.8": (98, 1200), "9.9.9.9": (10, 3), "1.1.1.1": (0, 0)}


class Reputation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_rep", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        cls.calls = []

        def fake_request(path, key, data=None, timeout=15):
            ip = path.split("ipAddress=")[1].split("&")[0]
            cls.calls.append(ip)
            s, r = SCORES.get(ip, (0, 0))
            return {"data": {"abuseConfidenceScore": s, "totalReports": r, "usageType": "Data Center", "isp": "X"}}, {}
        abuseipdb._request = fake_request

    def setUp(self):
        self.calls.clear()
        self.m._set_app_setting("abuseipdb_api_key", "k" * 40)
        self.m._set_app_setting("abuseipdb_critical_score", "75")
        self.m._rep_backoff_until = 0.0
        with self.m._db_connect() as c:
            c.execute("DELETE FROM abuse_rep_cache")

    def rec(self, msg, cat="auth_watch", sev="info", **kw):
        return {"id": "x", "epoch": time.time(), "host": "gate", "category": cat, "severity": sev, "message": msg, **kw}

    def test_login_success_from_bad_ip_becomes_critical(self):
        r = self.rec("ログイン成功: user=hit from=8.8.8.8 method=publickey")
        self.m._enrich_with_reputation(r)
        self.assertEqual(r["severity"], "critical")
        self.assertEqual(r["original_severity"], "info")
        self.assertIn("信頼度98%", r["message"])
        self.assertIn("CRITICALに引き上げ", r["message"])

    def test_login_success_from_clean_or_low_ip_is_untouched(self):
        for ip, expect_tag in (("9.9.9.9", True), ("1.1.1.1", False)):
            r = self.rec(f"ログイン成功: user=hit from={ip} method=publickey")
            self.m._enrich_with_reputation(r)
            self.assertEqual(r["severity"], "info")
            self.assertEqual("AbuseIPDB" in r["message"], expect_tag)

    def test_private_and_no_key_and_disabled_and_suppressed(self):
        r = self.rec("ログイン成功: user=hit from=192.168.0.118 method=publickey")
        self.m._enrich_with_reputation(r)
        self.assertEqual((r["severity"], self.calls), ("info", []))
        self.m._set_app_setting("abuseipdb_api_key", "")
        r = self.rec("ログイン成功: user=hit from=8.8.8.8")
        self.m._enrich_with_reputation(r)
        self.assertEqual((r["severity"], self.calls), ("info", []))
        self.m._set_app_setting("abuseipdb_api_key", "k" * 40)
        self.m._set_app_setting("abuseipdb_critical_score", "0")
        r = self.rec("ログイン成功: user=hit from=8.8.8.8")
        self.m._enrich_with_reputation(r)
        self.assertEqual(r["severity"], "info")
        self.m._set_app_setting("abuseipdb_critical_score", "75")
        r = self.rec("ログイン成功: user=hit from=8.8.8.8", suppressed=True)
        self.m._enrich_with_reputation(r)
        self.assertEqual(r["severity"], "info")

    def test_attack_uses_cache_only_and_warms_in_background(self):
        r = self.rec("SSHログイン失敗: user=root from=8.8.8.8", sev="warning")
        self.m._enrich_with_reputation(r)           # 未取得: タグは付かず、評判の照会は裏で行う
        self.assertNotIn("AbuseIPDB", r["message"])
        self.m._rep_pool.shutdown(wait=True)
        self.m._rep_pool = None
        self.assertEqual(self.calls, ["8.8.8.8"])
        r = self.rec("SSHログイン失敗: user=root from=8.8.8.8", sev="warning")
        self.m._enrich_with_reputation(r)           # 取得後: タグが付く。重大度は変えない
        self.assertIn("信頼度98%", r["message"])
        self.assertEqual(r["severity"], "warning")
        self.assertEqual(self.calls, ["8.8.8.8"])   # キャッシュで再照会しない

    def test_failure_backoff_and_budget(self):
        def boom(*a, **k):
            raise RuntimeError("429")
        orig, abuseipdb._request = abuseipdb._request, boom
        try:
            r = self.rec("ログイン成功: user=hit from=8.8.8.8")
            self.m._enrich_with_reputation(r)       # 失敗しても取り込みは続く
            self.assertEqual(r["severity"], "info")
            self.assertGreater(self.m._rep_backoff_until, time.time())
        finally:
            abuseipdb._request = orig
        with self.m._db_connect() as c:
            c.executemany("INSERT INTO abuse_rep_cache VALUES (?, 0, 0, '', '', ?)", [(f"10.0.0.{i}", time.time()) for i in range(self.m.REP_DAILY_BUDGET)])
        self.m._rep_backoff_until = 0.0
        self.assertIsNone(self.m._rep_lookup("8.8.8.8"))  # 1日の枠を使い切ったら照会しない


if __name__ == "__main__":
    unittest.main()
