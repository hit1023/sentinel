"""AIトリアージ応答のパース(app/ai_triage.py)のテスト。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import ai_triage  # noqa: E402


class ParseResponseTests(unittest.TestCase):
    def test_well_formed_response(self):
        r = ai_triage._parse_response("THREAT: NO\nビルド由来の一時プロセスと思われます。念のため親プロセスを確認してください。")
        self.assertFalse(r.is_threat)
        self.assertIn("ビルド由来", r.comment)

    def test_off_topic_response_is_discarded_and_kept_as_threat(self):
        # 実例: アラートと無関係な長文が返ってきた
        r = ai_triage._parse_response("相馬直樹監督が就任するというニュースを聞いたとき、ビールの世界では…")
        self.assertTrue(r.is_threat)
        self.assertIsNone(r.comment)

    def test_runaway_comment_is_discarded_even_if_format_is_followed(self):
        r = ai_triage._parse_response("THREAT: NO\n" + "あ" * 300)
        self.assertTrue(r.is_threat)  # 暴走した応答の「脅威ではない」判定は信用しない
        self.assertIsNone(r.comment)


if __name__ == "__main__":
    unittest.main()
