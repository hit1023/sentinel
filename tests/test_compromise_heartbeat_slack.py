import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
os.environ.setdefault("HITIDS_DATA_DIR", tempfile.mkdtemp())
import auth_watch  # noqa: E402


class FakeNotifier:
    def __init__(self):
        self.alerts = []

    def alert(self, category, message, severity="warning", allow_ai_dismiss=True):
        self.alerts.append((category, message, severity, allow_ai_dismiss))


def make_watcher(**cfg):
    cfg.setdefault("geoip_enabled", False)
    with patch.object(auth_watch.AuthWatcher, "_load_state",
                      lambda self: {"offsets": {}, "journal_cursor": None, "known_countries": [], "recent_fails": {}}):
        n = FakeNotifier()
        return auth_watch.AuthWatcher(cfg, n), n


def failed(ip, user="root"):
    return f"Failed password for {user} from {ip} port 5000 ssh2"


def accepted(ip, user="root"):
    return f"Accepted password for {user} from {ip} port 5000 ssh2"


class CompromiseTests(unittest.TestCase):
    def test_success_after_many_failures_is_critical_and_not_ai_dismissable(self):
        w, n = make_watcher(compromise_min_failures=5)
        for _ in range(5):
            w._process_line(failed("203.0.113.9"))
        n.alerts.clear()
        w._process_line(accepted("203.0.113.9"))
        self.assertEqual(len(n.alerts), 1)
        cat, msg, sev, allow = n.alerts[0]
        self.assertEqual((cat, sev, allow), ("auth_watch", "critical", False))
        self.assertIn("侵入成功の疑い", msg)
        self.assertIn("from=203.0.113.9", msg)  # SSH許可リストがfrom=で照合できる形式

    def test_few_failures_or_other_ip_is_plain_info(self):
        w, n = make_watcher(compromise_min_failures=5)
        for _ in range(4):
            w._process_line(failed("203.0.113.9"))
        n.alerts.clear()
        w._process_line(accepted("203.0.113.9"))
        w._process_line(accepted("198.51.100.1"))
        self.assertEqual([a[2] for a in n.alerts], ["info", "info"])

    def test_alerts_once_per_attack_and_expires_outside_window(self):
        w, n = make_watcher(compromise_min_failures=3, compromise_window_seconds=60)
        for _ in range(3):
            w._process_line(failed("203.0.113.9"))
        n.alerts.clear()
        w._process_line(accepted("203.0.113.9"))
        w._process_line(accepted("203.0.113.9"))
        self.assertEqual([a[2] for a in n.alerts], ["critical", "info"])
        # 窓外の古い失敗は数えない
        w._state["recent_fails"]["198.51.100.7"] = [[time.time() - 3600, "root"]] * 10
        n.alerts.clear()
        w._process_line(accepted("198.51.100.7"))
        self.assertEqual([a[2] for a in n.alerts], ["info"])

    def test_can_be_disabled(self):
        w, n = make_watcher(compromise_detection=False, compromise_min_failures=1)
        w._process_line(failed("203.0.113.9"))
        n.alerts.clear()
        w._process_line(accepted("203.0.113.9"))
        self.assertEqual([a[2] for a in n.alerts], ["info"])


try:
    import fastapi  # noqa: F401
    HAVE_WEBUI = True
except ImportError:
    HAVE_WEBUI = False


@unittest.skipUnless(HAVE_WEBUI, "fastapi未インストール")
class WebuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["IDS_DATA_DIR"] = cls.tmp
        import importlib.util
        spec = importlib.util.spec_from_file_location("webui_main", ROOT / "webui" / "main.py")
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.m._init_db()

    def test_slack_payload_escapes_mentions_and_threshold(self):
        m = self.m
        rec = {"host": "h", "category": "c", "severity": "critical", "message": "<!channel> & <x>", "timestamp": "t"}
        text = m._build_slack_payload(rec, "<!here>")["blocks"][1]["text"]["text"]
        self.assertNotIn("<!channel>", text)
        self.assertIn("&lt;!channel&gt;", text)
        sent = []
        with patch.object(m, "_post_slack", lambda url, p: sent.append(p)):
            m._set_app_setting("slack_enabled", "true")
            m._set_app_setting("slack_webhook_url", "https://hooks.slack.com/services/T/B/X")
            m._set_app_setting("slack_min_severity", "critical")
            m._send_slack_alert({**rec, "severity": "warning"})
            self.assertEqual(sent, [])
            m._send_slack_alert(rec)
            self.assertEqual(len(sent), 1)
            m._set_app_setting("slack_enabled", "false")
            m._send_slack_alert(rec)
            self.assertEqual(len(sent), 1)

    def test_post_slack_rejects_non_slack_urls(self):
        with self.assertRaises(ValueError):
            self.m._post_slack("http://169.254.169.254/", {})

    def test_heartbeat_down_and_recovery_once(self):
        m = self.m
        m._STARTED_AT = 0
        m._set_app_setting("heartbeat_enabled", "true")
        m._set_app_setting("heartbeat_grace_seconds", "300")
        m._set_app_setting("heartbeat_ignore_hosts", "planned")
        m._write_heartbeat_state({})
        t = 10_000.0
        m._write_hosts_status({
            "a": {"host": "a", "received_at": t},
            "planned": {"host": "planned", "received_at": t},
            "old": {"host": "old", "received_at": t - 99999},
        })
        self.assertEqual(m.check_heartbeats(now=t + 10), [])  # 初回は静かに記録
        self.assertEqual(m.check_heartbeats(now=t + 100), [])
        down = m.check_heartbeats(now=t + 1000)  # a, plannedが途絶
        self.assertEqual([r["host"] for r in down], ["a"])
        self.assertEqual(down[0]["severity"], "warning")
        self.assertEqual(m.check_heartbeats(now=t + 1100), [])  # 再通知しない
        hs = m._read_hosts_status()
        hs["a"]["received_at"] = t + 1190
        m._write_hosts_status(hs)
        up = m.check_heartbeats(now=t + 1200)
        self.assertEqual([(r["host"], r["severity"]) for r in up], [("a", "info")])


if __name__ == "__main__":
    unittest.main()
