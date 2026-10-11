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


class Pure(unittest.TestCase):
    def test_categories_and_comment_have_no_internal_info(self):
        self.assertEqual(abuseipdb.categories_for({"ssh": 6}), [18, 22])
        self.assertEqual(abuseipdb.categories_for({"ssh": 1, "web": 2}), [18, 21, 22])
        c = abuseipdb.build_comment(8, {"ssh": 6, "web": 2})
        self.assertIn("6 failed SSH", c)
        for bad in ("gate", "192.168", "h-1", "mac-mini"):
            self.assertNotIn(bad, c)


class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_abuse", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        now = time.time()
        for i in range(6):   # 8.8.8.8: SSH 6回 → 候補
            cls.m._persist_important({"id": f"s{i}", "epoch": now - 600 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                      "severity": "warning", "message": f"SSHログイン失敗: user=root from=8.8.8.8 port=22"})
        for i in range(2):   # 9.9.9.9: 2回 → 回数不足
            cls.m._persist_important({"id": f"t{i}", "epoch": now - 700 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                      "severity": "warning", "message": "SSHログイン失敗: user=root from=9.9.9.9 port=22"})
        for i in range(6):   # 1.1.1.1: 研究スキャナー → 除外
            cls.m._persist_important({"id": f"u{i}", "epoch": now - 800 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                      "severity": "warning", "message": "SSHログイン失敗: user=root from=1.1.1.1 port=22"})
        for i in range(6):   # 4.4.4.4: ログイン成功の疑い → 対象外の種類
            cls.m._persist_important({"id": f"v{i}", "epoch": now - 900 - i, "timestamp": "t", "host": "gate", "category": "auth_watch",
                                      "severity": "critical", "message": "不審ログイン成功: user=hit from=4.4.4.4 ログイン成功"})
        geo = {ip: {"lat": 1, "lon": 1, "country": "T", "country_code": "TT", "city": ""} for ip in ("8.8.8.8", "9.9.9.9", "1.1.1.1", "4.4.4.4")}
        cls.m.attack_map._geo = lambda ips: {i: geo[i] for i in ips if i in geo}
        cls.m.publicfeed.lookup_asn = lambda c, ips: {i: ({"asn": "AS1", "name": "CENSYS", "org": "Censys"} if i == "1.1.1.1" else {"asn": "AS9", "name": "NET", "org": "x"}) for i in ips}
        cls.sent = []
        abuseipdb._request = lambda path, key, data=None, timeout=15: (
            cls.sent.append((path, key, data)) or ({"data": {"abuseConfidenceScore": 42}}, {"X-RateLimit-Remaining": "999", "X-RateLimit-Limit": "1000"}))

    def test_flow(self):
        m = self.m
        self.assertFalse(m.api_get_abuse_settings()["configured"])
        c = m.api_abuse_candidates()
        self.assertEqual([x["ip"] for x in c["candidates"]], ["8.8.8.8"])
        self.assertEqual(c["candidates"][0]["categories"], [18, 22])
        with self.assertRaises(Exception):
            asyncio.run(m.api_abuse_report({"ip": "8.8.8.8"}))   # キー未設定
        asyncio.run(m.api_set_abuse_settings({"api_key": "a" * 40, "min_events": 5}))
        s = m.api_get_abuse_settings()
        self.assertTrue(s["configured"])
        self.assertNotIn("a" * 10, str(s))                       # キーは返さない
        with self.assertRaises(Exception):
            asyncio.run(m.api_abuse_report({"ip": "9.9.9.9"}))    # 候補でないIPは送れない
        with self.assertRaises(Exception):
            asyncio.run(m.api_abuse_report({"ip": "1.1.1.1"}))
        r = asyncio.run(m.api_abuse_report({"ip": "8.8.8.8"}))
        self.assertEqual(r["score"], 42)
        path, key, data = self.sent[-1]
        self.assertEqual((path, key, data["ip"], data["categories"]), ("/report", "a" * 40, "8.8.8.8", "18,22"))
        self.assertNotIn("gate", data["comment"])
        self.assertEqual(m.api_abuse_candidates()["candidates"], [])  # 通報済みは24時間出ない
        with self.assertRaises(Exception):
            asyncio.run(m.api_abuse_report({"ip": "8.8.8.8"}))        # 二重通報の防止


if __name__ == "__main__":
    unittest.main()
