import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def alert(self, category, message, severity, **kw):
        self.sent.append((category, message, severity))


class AgentResolve(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.mkdtemp()
        os.environ["HITIDS_DATA_DIR"] = self.data
        for m in ("paths", "secretscan", "secret_watch"):
            sys.modules.pop(m, None)
        import secret_watch
        self.sw = secret_watch
        self.root = tempfile.mkdtemp()
        self.repo = os.path.join(self.root, "r1")
        os.makedirs(self.repo)
        import subprocess
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        self.env = os.path.join(self.repo, ".env")
        with open(self.env, "w") as f:
            f.write("X=1\n")
        os.chmod(self.env, 0o644)

    def _watcher(self):
        n = FakeNotifier()
        w = self.sw.SecretWatcher({"scan_roots": [self.root], "interval_hours": 24}, n)
        return w, n

    def test_fix_is_reported_as_resolved_on_forced_rescan(self):
        w, n = self._watcher()
        w.check(force=True)
        self.assertTrue(any("他のユーザーから読める" in m for _, m, _ in n.sent), n.sent)
        n.sent.clear()
        os.chmod(self.env, 0o600)
        w.check()  # 24時間以内なので走査しない
        self.assertEqual(n.sent, [])
        w.request_rescan()
        w.check()
        self.assertEqual(len(n.sent), 1, n.sent)
        self.assertTrue(n.sent[0][1].startswith("解消を確認: repo=r1"), n.sent)
        self.assertEqual(n.sent[0][2], "info")
        n.sent.clear()
        w.check(force=True)
        self.assertEqual(n.sent, [])  # 解消済みは二度と通知しない

    def test_deleted_repo_is_reported_as_resolved(self):
        import shutil
        w, n = self._watcher()
        w.check(force=True)
        self.assertTrue(any("repo=r1" in m for _, m, _ in n.sent))
        n.sent.clear()
        # 別のリポジトリが残っている状態で、r1だけが削除された
        other = os.path.join(self.root, "r2")
        os.makedirs(other)
        import subprocess
        subprocess.run(["git", "init", "-q", other], check=True)
        shutil.rmtree(self.repo)
        w.check(force=True)
        self.assertEqual(len(n.sent), 1, n.sent)
        self.assertTrue(n.sent[0][1].startswith("解消を確認: repo=r1"), n.sent)
        n.sent.clear()
        w.check(force=True)
        self.assertEqual(n.sent, [])

    def test_unreadable_root_does_not_resolve(self):
        w, n = self._watcher()
        w.check(force=True)
        n.sent.clear()
        w.roots = [os.path.join(self.root, "missing")]   # ディスクが外れている等
        w.check(force=True)
        self.assertFalse(any(m.startswith("解消を確認") for _, m, _ in n.sent), n.sent)

    def test_unfixed_is_not_repeated(self):
        w, n = self._watcher()
        w.check(force=True)
        n.sent.clear()
        w.check(force=True)
        self.assertEqual(n.sent, [])


class ManagerResolve(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp()
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main_rescan", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()

    def test_resolved_notice_acks_old_alerts_and_command_is_delivered(self):
        m = self.m
        now = time.time()
        m._persist_important({"id": "a1", "epoch": now, "timestamp": "t", "host": "mac-mini", "category": "secret_watch",
                              "severity": "warning", "message": "秘密情報ファイルが他のユーザーから読める権限です: repo=pm-tool 1件（world-readable-secret-file×1）"})
        m._persist_important({"id": "a2", "epoch": now, "timestamp": "t", "host": "mac-mini", "category": "secret_watch",
                              "severity": "warning", "message": "秘密情報ファイルが他のユーザーから読める権限です: repo=other 1件（world-readable-secret-file×1）"})
        self.assertEqual(m.api_secrets()["open_warning"], 2)
        m._resolve_secret_alerts({"id": "n1", "host": "mac-mini", "category": "secret_watch",
                                  "message": "解消を確認: repo=pm-tool 前回の検知1件がすべて解消されました"})
        d = m.api_secrets()
        self.assertEqual(d["open_warning"], 1)
        self.assertEqual([i["repo"] for i in d["items"] if not i["acked"]], ["other"])
        # 別ホストの同名リポジトリには影響しない
        m._resolve_secret_alerts({"id": "n2", "host": "h-1", "category": "secret_watch", "message": "解消を確認: repo=other 1件"})
        self.assertEqual(m.api_secrets()["open_warning"], 1)

        import asyncio
        m._write_hosts_status({"mac-mini": {"host": "mac-mini"}})
        self.assertEqual(m.api_secrets_rescan()["hosts"], ["mac-mini"])
        r = asyncio.run(m.ingest_status({"host": "mac-mini"}, authorization=f"Bearer {m.INGEST_TOKEN}" if m.INGEST_TOKEN else None))
        self.assertEqual(r["commands"], ["secret_rescan"])
        r = asyncio.run(m.ingest_status({"host": "mac-mini"}, authorization=f"Bearer {m.INGEST_TOKEN}" if m.INGEST_TOKEN else None))
        self.assertEqual(r["commands"], [])


if __name__ == "__main__":
    unittest.main()
