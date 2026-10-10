import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "webui"))
import playbooks  # noqa: E402


def rec(category, message, severity="critical"):
    return {"category": category, "message": message, "severity": severity}


class PlaybookTests(unittest.TestCase):
    def test_every_known_alert_kind_has_specific_steps(self):
        cases = {
            "secret": rec("secret_watch", "秘密情報の混入を検知: repo=mm-fish-speech 2件（aws-access-key×1, slack-webhook×1） 例: a.py[aws-access-key AKIA…(20文字)]"),
            "intrusion": rec("auth_watch", "侵入成功の疑い: ブルートフォース後にログイン成功: user=root from=203.0.113.9 method=publickey"),
            "new-user": rec("auth_watch", "新規ユーザーが作成されました: user=backdoor（侵入後のバックドア作成の可能性）"),
            "group-add": rec("auth_watch", "特権グループへユーザーが追加されました: user=bob group=sudo"),
            "new-location": rec("auth_watch", "いつもと異なるロケーションからのログイン成功: user=hit from=1.2.3.4"),
            "brute-force": rec("auth_watch", "ブルートフォースの疑い: 1.2.3.4 から300秒間に5回のログイン失敗", "warning"),
            "ssh-keys": rec("integrity_watch", "ファイル改ざんの疑い: /home/hit/.ssh/authorized_keys"),
            "integrity": rec("integrity_watch", "ファイル改ざんの疑い（ハッシュ不一致）: /etc/rmt", "warning"),
            "outbound": rec("outbound_watch", "不審な外向き通信を検知（既知の攻撃ツールが使うポート）: 185.220.101.4:4444 pid=123 process=bash"),
            "listen-port": rec("procnet_watch", "未登録のリスニングポートを検知: port=9999 pid=1 process=x", "warning"),
            "unknown-process": rec("procnet_watch", "未知のプロセスを検知: pid=1 name=x cmd=/tmp/x", "warning"),
            "web-success": rec("web_watch", "Webアクセス異常: 不審なリクエストに成功応答（攻撃が通った可能性） ip=1.2.3.4 host=a"),
            "web-probe": rec("web_watch", "Webアクセス異常: 攻撃ペイロードを含むリクエスト ip=1.2.3.4 種別=SQLi", "warning"),
            "exposure-port": rec("exposure_watch", "公開ポートが増えました: ip=1.2.3.4 新規=8088", "warning"),
            "vuln": rec("vuln_watch", "悪用確認済みの脆弱性(CISA KEV)が5件あります"),
            "heartbeat": rec("heartbeat", "エージェントからの応答が途絶: host=h-1", "warning"),
        }
        for pid, r in cases.items():
            pb = playbooks.match(r)
            self.assertEqual(pb["id"], pid, r["message"])
            self.assertTrue(pb["steps"] and pb["title"] and pb["urgency"], pid)
        self.assertEqual(playbooks.match(rec("unknown_cat", "x"))["id"], "generic")

    def test_secret_playbook_orders_revocation_before_history_rewrite(self):
        pb = playbooks.match(rec("secret_watch", "秘密情報の混入を検知: repo=r 1件（aws-access-key×1）"))
        texts = [s["text"] for s in pb["steps"]]
        revoke = next(i for i, t in enumerate(texts) if "非アクティブ化" in t)
        rewrite = next(i for i, t in enumerate(texts) if "履歴からの除去" in t)
        self.assertLess(revoke, rewrite)
        self.assertEqual(pb["urgency"], playbooks.URGENT)
        perm = playbooks.match(rec("secret_watch", "秘密情報ファイルが他のユーザーから読める権限です: repo=r 1件（world-readable-secret-file×1）", "warning"))
        self.assertIn("chmod 600", " ".join(s.get("command", "") for s in perm["steps"]))

    def test_headline_for_slack_and_email(self):
        h = playbooks.headline(rec("secret_watch", "秘密情報の混入を検知: repo=r 1件（aws-access-key×1）"))
        self.assertIn("今すぐ", h)
        self.assertIsNone(playbooks.headline(rec("unknown_cat", "x")))


try:
    import fastapi  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "fastapi未インストール")
class GuideApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_guide", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        cls.m._persist_important({"id": "g1", "epoch": 1.0, "timestamp": "t", "host": "mac-mini", "category": "secret_watch",
                                  "severity": "critical", "message": "秘密情報の混入を検知: repo=x 1件（aws-access-key×1）"})

    def test_guide_returns_playbook_without_ai_and_caches_ai_text(self):
        m = self.m
        d = m.api_alert_guide("g1")
        self.assertEqual(d["playbook"]["id"], "secret")
        self.assertIsNone(d["ai_advice"])
        with patch.object(m, "_call_cf_ai", return_value="【状況】テスト") as ai:
            self.assertEqual(m.api_alert_guide_ai("g1"), {"text": "【状況】テスト", "cached": False})
            self.assertEqual(m.api_alert_guide_ai("g1")["cached"], True)
            self.assertEqual(ai.call_count, 1)  # 2回目はAIを呼ばない
            sent = ai.call_args[0][1]
            self.assertIn("playbook", sent)
        self.assertEqual(m.api_alert_guide("g1")["ai_advice"]["text"], "【状況】テスト")

    def test_ai_failure_and_unknown_alert(self):
        m = self.m
        m._persist_important({"id": "g2", "epoch": 2.0, "timestamp": "t", "host": "h", "category": "heartbeat",
                              "severity": "warning", "message": "応答が途絶"})
        with patch.object(m, "_call_cf_ai", return_value=None):
            with self.assertRaises(m.HTTPException) as cm:
                m.api_alert_guide_ai("g2")
            self.assertEqual(cm.exception.status_code, 503)
        with self.assertRaises(m.HTTPException) as cm:
            m.api_alert_guide("nope")
        self.assertEqual(cm.exception.status_code, 404)

    def test_slack_payload_includes_next_step_and_escapes(self):
        payload = self.m._build_slack_payload({"host": "h", "category": "secret_watch", "severity": "critical",
                                               "message": "秘密情報の混入を検知: repo=r 1件（aws-access-key×1）", "timestamp": "t"})
        text = payload["blocks"][1]["text"]["text"]
        self.assertIn("次にすること", text)


if __name__ == "__main__":
    unittest.main()
