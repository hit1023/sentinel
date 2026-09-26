import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import web_watch
import notify
import ai_triage


def common(path, status=404, date=None):
    date = date or datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'203.0.113.8 - - [{date}] "GET {path} HTTP/1.1" {status} 123 "-" "test"\n'


class Notifier:
    def __init__(self):
        self.alerts = []

    def alert(self, *args):
        self.alerts.append(args)


class WebWatchTests(unittest.TestCase):
    def test_parses_nginx_and_npm_without_trusting_forwarded_headers(self):
        self.assertEqual(web_watch.parse_line(common("/.env?token=abc"))[3:], ("/.env", 404))
        npm = ('[26/Sep/2026:12:00:00 +0900] - 404 404 - GET https app.example '
               '"/.git/config" [Client 2001:db8::1] [Length 12] [Gzip -] '
               '[Sent-to 10.0.0.1] "bot" "-"\n')
        self.assertEqual(web_watch.parse_line(npm)[1:5],
                         ("2001:db8::1", "app.example", "/.git/config", 404))
        self.assertIsNone(web_watch.parse_line("not an access log"))

    def test_initial_tail_partial_line_rotation_and_scan_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(common("/old"), encoding="utf-8")
            notifier = Notifier()
            with patch.object(web_watch, "STATE_PATH", str(Path(tmp) / "state.json")), \
                 patch.dict(os.environ, {"HITIDS_FS_PREFIX": ""}, clear=False):
                watcher = web_watch.WebWatcher({"log_paths": [str(path)], "scan_distinct_paths": 2}, notifier)
                watcher.check()
                self.assertFalse(notifier.alerts)
                with path.open("a") as f:
                    f.write(common("/.env") + common("/.git/config").rstrip("\n"))
                watcher.check()
                self.assertFalse(notifier.alerts)  # incomplete line must wait
                with path.open("a") as f:
                    f.write("\n")
                watcher.check()
                self.assertEqual(len(notifier.alerts), 1)
                self.assertIn("機密・管理パス", notifier.alerts[0][1])
                path.rename(Path(tmp) / "access.log.1")
                path.write_text(common("/wp-admin") + common("/phpmyadmin"), encoding="utf-8")
                watcher.check()
                self.assertEqual(len(notifier.alerts), 1)  # cooldown
                restarted = web_watch.WebWatcher({"log_paths": [str(path)]}, notifier)
                restarted.check()
                self.assertEqual(len(notifier.alerts), 1)  # persisted offset

    def test_web_alert_cannot_be_downgraded_by_ai(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(ai_triage, "triage", return_value=ai_triage.TriageResult(False, "正常と判定")):
            n = notify.Notifier({"log_file": str(Path(tmp) / "alerts.log")},
                                {"auto_dismiss_non_threats": True}, {"enabled": False})
            with patch.object(n, "_send_central") as central:
                n.alert("web_watch", "Webアクセス異常", "warning")
            self.assertFalse(central.called)
            self.assertIn("[WARNING]", (Path(tmp) / "alerts.log").read_text())


if __name__ == "__main__":
    unittest.main()
