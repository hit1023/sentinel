import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui"))
import publicfeed as pf

NOW = 1_800_000_000.0


def ev(ip, kind, hours_ago):
    return {"ip": ip, "kind": kind, "epoch": NOW - hours_ago * 3600, "host": "gate", "id": "x"}


GEO = {ip: {"country_code": "XX", "country": "Testland", "lat": 35.6895, "lon": 139.6917}
       for ip in ("8.8.8.8", "9.9.9.9", "1.1.1.1", "4.4.4.4", "2606:4700:4700::1111")}
ASN = {"8.8.8.8": {"asn": "AS15169", "name": "GOOGLE", "org": "Google"},
       "9.9.9.9": {"asn": "AS19281", "name": "QUAD9", "org": "Quad9"},
       "1.1.1.1": {"asn": "AS1", "name": "CENSYS-ARIN", "org": "Censys, Inc."}}


class PublicFeed(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(pf.mask_ip("203.0.113.77"), "203.0.113.x")
        self.assertTrue(pf.mask_ip("2606:4700:4700::1111").endswith("::x"))
        self.assertNotIn("1111", pf.mask_ip("2606:4700:4700::1111"))

    def test_feed_filters(self):
        events = (
            [ev("8.8.8.8", "ssh", 5)] * 5 + [ev("8.8.8.8", "web", 6)] * 2   # 載る（7件）
            + [ev("9.9.9.9", "ssh", 3)] * 2                                   # 少なすぎ→載らない
            + [ev("1.1.1.1", "ssh", 4)] * 9                                   # 研究スキャナー→載らない
            + [ev("4.4.4.4", "ssh", 0.2)] * 9                                 # 直近1時間は出さない
            + [ev("4.4.4.4", "login", 5)] * 9                                 # ログイン成功は出さない
            + [ev("4.4.4.4", "outbound", 5)] * 9 + [ev("4.4.4.4", "webbreach", 5)] * 9
            + [ev("2606:4700:4700::1111", "ssh", 30)] * 9                     # 24時間より前
        )
        feed = pf.build(events, GEO, ASN, NOW)
        self.assertEqual([s["ip"] for s in feed["sources"]], ["8.8.8.x"])
        s = feed["sources"][0]
        self.assertEqual((s["count"], s["asn"], s["network"]), (7, "AS15169", "GOOGLE"))
        self.assertEqual(feed["totals"]["events"], 7)
        self.assertEqual(sum(feed["hourly"]), 7)
        self.assertEqual(s["lat"], 35.7)

    def test_no_internal_info_leaks(self):
        feed = pf.build([ev("8.8.8.8", "ssh", 5)] * 5, GEO, ASN, NOW)
        text = str(feed)
        for secret in ("gate", "8.8.8.8", "host"):
            self.assertNotIn(secret, text)
        self.assertTrue(feed["sources"][0]["last_seen"].endswith(":00:00Z"))


if __name__ == "__main__":
    unittest.main()
