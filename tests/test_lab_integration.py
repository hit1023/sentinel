"""Exercise the lab's HTTP requests through the real web log watcher."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from lab.server import make_handler
import web_watch


class Capture:
    def __init__(self):
        self.alerts = []

    def alert(self, *args):
        self.alerts.append(args)


class LabIntegrationTests(unittest.TestCase):
    def test_lab_requests_trigger_sentinel_web_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "access.log"
            log_file.touch()
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(log_file))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"

            def fetch(path):
                try:
                    with urllib.request.urlopen(base + path) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    return error.code, json.load(error)

            try:
                captured = Capture()
                with patch.object(web_watch, "STATE_PATH", str(Path(tmp) / "watch-state.json")), \
                     patch.dict(os.environ, {"HITIDS_FS_PREFIX": "", "WEB_LOG_PATHS": ""}):
                    watcher = web_watch.WebWatcher({"log_paths": [str(log_file)]}, captured)
                    watcher.check()  # initial tail
                    self.assertEqual(fetch("/files?name=..%2Fsecrets%2Fkeys.txt")[0], 200)
                    self.assertEqual(fetch("/files?name=..%2Fsecrets%2Fkeys.txt&mode=fixed")[0], 403)
                    for path in ("/.env", "/.git/config", "/wp-admin", "/phpmyadmin", "/cgi-bin/status"):
                        self.assertEqual(fetch("/probe" + path)[0], 404)
                    watcher.check()
                self.assertEqual(len(captured.alerts), 2)
                self.assertTrue(all(a[0] == "web_watch" for a in captured.alerts))
                self.assertTrue(any("パスの境界越え" in a[1] for a in captured.alerts))
                self.assertTrue(any("機密・管理パスの探索" in a[1] for a in captured.alerts))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
