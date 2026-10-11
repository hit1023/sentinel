import json
import os
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SecretsPanelAndRotation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_secrets", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()
        now = time.time()
        cls.m._persist_important({"id": "s1", "epoch": now, "timestamp": "t1", "host": "mac-mini", "category": "secret_watch",
                                  "severity": "critical", "message": "秘密情報の混入を検知（初回走査）: repo=mm 4件（slack-webhook×2, aws-access-key×2） 例: a.ipynb@10e6f7e[aws-access-key AKIA…(20文字)]"})
        cls.m._persist_important({"id": "s2", "epoch": now, "timestamp": "t2", "host": "mac-mini", "category": "secret_watch",
                                  "severity": "warning", "message": "秘密情報ファイルが他のユーザーから読める権限です: repo=pm 1件（world-readable-secret-file×1） 例: .env[mode=644]"})

    def test_listing_and_ack(self):
        m = self.m
        d = m.api_secrets()
        self.assertEqual((d["open_critical"], d["open_warning"]), (1, 1))
        crit = next(i for i in d["items"] if i["id"] == "s1")
        self.assertEqual(crit["repo"], "mm")
        self.assertTrue(crit["history"])
        self.assertEqual({k["rule"]: k["count"] for k in crit["kinds"]}, {"slack-webhook": 2, "aws-access-key": 2})
        m.api_secret_ack("s1")
        d = m.api_secrets()
        self.assertEqual(d["open_critical"], 0)
        self.assertEqual(d["acked"], 1)
        m.api_secret_unack("s1")
        self.assertEqual(m.api_secrets()["open_critical"], 1)

    def test_rotation(self):
        m = self.m
        m.ALERTS_JSONL = os.path.join(tempfile.mkdtemp(), "alerts.jsonl")
        m.ALERTS_MAX_BYTES = 200
        for i in range(20):
            m._append_alert({"i": i, "pad": "x" * 50})
        self.assertTrue(os.path.exists(m.ALERTS_JSONL + ".1"))
        # 世代は1つだけ保持するため古いものは消える。最新の記録は必ず現行ファイルに残る
        last = [json.loads(l) for l in open(m.ALERTS_JSONL)][-1]
        self.assertEqual(last["i"], 19)
        self.assertLess(os.path.getsize(m.ALERTS_JSONL), 400)


if __name__ == "__main__":
    unittest.main()
