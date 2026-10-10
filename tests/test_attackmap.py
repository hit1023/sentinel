"""ATTACK MAP(webui/attackmap.py)の集計テスト。位置情報APIはモックする。"""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "webui"))
import attackmap  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_attack_alerts_are_mapped(self):
        self.assertEqual(
            attackmap.classify({"category": "auth_watch", "message": "存在しないユーザーへのログイン試行: user=admin from=218.92.0.112"}),
            ("218.92.0.112", "ssh"),
        )
        self.assertEqual(
            attackmap.classify({"category": "auth_watch", "message": "ブルートフォースの疑い: 61.177.172.140 から300秒間に5回のログイン失敗"}),
            ("61.177.172.140", "ssh"),
        )
        self.assertEqual(
            attackmap.classify({"category": "web_watch", "message": "Webアクセス異常: 機密パス探索 ip=185.220.101.4 件数=12 期間=300秒"}),
            ("185.220.101.4", "web"),
        )
        self.assertEqual(
            attackmap.classify({"category": "auth_watch", "message": "いつもと異なるロケーションからのログイン成功: user=hit from=2.57.122.33 method=publickey"}),
            ("2.57.122.33", "login"),
        )

    def test_web_success_response_is_a_breach(self):
        self.assertEqual(
            attackmap.classify({"category": "web_watch", "message": "Webアクセス異常: 不審なリクエストに成功応答（攻撃が通った可能性） ip=185.220.101.4 件数=1 期間=300秒 host=a.example"}),
            ("185.220.101.4", "webbreach"))
        self.assertEqual(
            attackmap.classify({"category": "web_watch", "message": "Webアクセス異常: 攻撃ペイロードを含むリクエスト ip=185.220.101.4 件数=1 期間=300秒 種別=SQLi"}),
            ("185.220.101.4", "web"))

    def test_normal_logins_lan_and_other_categories_are_ignored(self):
        self.assertIsNone(attackmap.classify({"category": "auth_watch", "message": "ログイン成功: user=hit from=203.0.113.9 method=publickey"}))
        self.assertIsNone(attackmap.classify({"category": "auth_watch", "message": "存在しないユーザーへのログイン試行: user=a from=192.168.0.118"}))
        self.assertIsNone(attackmap.classify({"category": "integrity_watch", "message": "ip=8.8.8.8"}))


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = str(Path(self.tmp.name) / "t.db")

        def connect():
            conn = sqlite3.connect(db)
            conn.row_factory = sqlite3.Row
            return conn

        self.map = attackmap.AttackMap(connect)
        self.calls = []

    def fake_urlopen(self, req, timeout=10):
        import io
        import json
        ips = json.loads(req.data.decode())
        self.calls.append(ips)
        geo = {"218.92.0.112": ("CN", 31.7, 118.8), "185.220.101.4": ("DE", 52.6, 13.1)}
        out = [{"status": "success", "query": ip, "lat": geo[ip][1], "lon": geo[ip][2],
                "country": geo[ip][0], "countryCode": geo[ip][0], "city": ""} if ip in geo
               else {"status": "fail", "query": ip} for ip in ips]

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return Resp(json.dumps(out).encode())

    def test_aggregates_by_ip_and_country_and_caches_geo(self):
        records = [
            {"id": "1", "epoch": 1, "host": "gate", "category": "auth_watch", "severity": "warning",
             "message": "存在しないユーザーへのログイン試行: user=a from=218.92.0.112"},
            {"id": "2", "epoch": 2, "host": "h-1", "category": "auth_watch", "severity": "warning",
             "message": "存在しないユーザーへのログイン試行: user=b from=218.92.0.112"},
            {"id": "3", "epoch": 3, "host": "gate", "category": "web_watch", "severity": "warning",
             "message": "Webアクセス異常: スキャン ip=185.220.101.4 件数=9 期間=300秒"},
            {"id": "4", "epoch": 4, "host": "gate", "category": "web_watch", "severity": "warning",
             "message": "Webアクセス異常: スキャン ip=45.83.64.1 件数=9 期間=300秒"},  # 位置不明（APIがfailを返す）
        ]
        with patch.object(attackmap.urllib.request, "urlopen", self.fake_urlopen):
            data = self.map.build(records)
            self.map.build(records)  # 2回目はキャッシュから（失敗IPも24時間は再問い合わせしない）
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(data["total_events"], 4)
        self.assertEqual(data["located_events"], 3)
        top = data["sources"][0]
        self.assertEqual((top["ip"], top["count"], top["hosts"]), ("218.92.0.112", 2, ["gate", "h-1"]))
        self.assertEqual([c["cc"] for c in data["top_countries"]], ["CN", "DE"])


if __name__ == "__main__":
    unittest.main()
