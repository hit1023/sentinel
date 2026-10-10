import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
os.environ.setdefault("HITIDS_DATA_DIR", tempfile.mkdtemp())
import auth_watch  # noqa: E402
import secret_watch  # noqa: E402
import secretscan  # noqa: E402


class Notifier:
    def __init__(self):
        self.alerts = []

    def alert(self, category, message, severity="warning", allow_ai_dismiss=True):
        self.alerts.append((category, message, severity, allow_ai_dismiss))


def watcher(**cfg):
    with patch.object(auth_watch.AuthWatcher, "_load_state",
                      lambda self: {"offsets": {}, "journal_cursor": None, "known_countries": [], "recent_fails": {}}):
        n = Notifier()
        return auth_watch.AuthWatcher({"geoip_enabled": False, **cfg}, n), n


HDR = "Oct 11 03:00:01 gate"


class PrivilegeEventTests(unittest.TestCase):
    def sev(self, line, **cfg):
        w, n = watcher(**cfg)
        w._process_line(line)
        return [(a[2], a[1]) for a in n.alerts]

    def test_new_user_and_privileged_group_are_critical(self):
        r = self.sev(f"{HDR} useradd[1234]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash")
        self.assertEqual(r[0][0], "critical")
        self.assertIn("backdoor", r[0][1])
        r = self.sev(f"{HDR} usermod[99]: add 'bob' to group 'sudo'")
        self.assertEqual(r[0][0], "critical")
        r = self.sev(f"{HDR} usermod[99]: add 'bob' to shadow group 'sudo'")
        self.assertEqual(r[0][0], "critical")
        r = self.sev(f"{HDR} gpasswd[5]: user bob added by root to group docker")
        self.assertEqual(r[0][0], "critical")
        self.assertEqual(self.sev(f"{HDR} usermod[99]: add 'bob' to group 'staff'"), [])

    def test_su_sudo_failure_and_password_change_are_warnings(self):
        self.assertEqual(self.sev(f"{HDR} su: (to root) hit on pts/0")[0][0], "warning")
        self.assertEqual(self.sev(f"{HDR} sudo:  bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")[0][0], "warning")
        self.assertEqual(self.sev(f"{HDR} sudo:  bob : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/ls")[0][0], "warning")
        self.assertEqual(self.sev(f"{HDR} passwd[7]: pam_unix(passwd:chauthtok): password changed for bob")[0][0], "warning")
        # 正常なsudo成功は通知しない
        self.assertEqual(self.sev(f"{HDR} sudo:      hit : TTY=pts/0 ; PWD=/home/hit ; USER=root ; COMMAND=/usr/bin/apt update"), [])

    def test_forged_log_lines_via_ssh_username_do_not_trigger(self):
        forged = f"{HDR} sshd[1]: Invalid user useradd[1]: new user: name=x, from 203.0.113.9 port 22"
        w, n = watcher()
        w._process_line(forged)
        self.assertFalse([a for a in n.alerts if a[2] == "critical" and "新規ユーザー" in a[1]])

    def test_can_be_disabled(self):
        self.assertEqual(self.sev(f"{HDR} useradd[1]: new user: name=x, UID=1", privilege_events=False), [])


class SecretWatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = patch.object(secret_watch, "STATE_PATH", str(Path(self.tmp.name) / "state.json"))
        self.state.start()
        self.addCleanup(self.state.stop)
        self.repo = Path(self.tmp.name) / "proj"
        self.repo.mkdir()
        run = lambda *a: subprocess.run(["git", "-C", str(self.repo), *a], capture_output=True, check=True)
        run("init", "-q")
        run("config", "user.email", "t@example.com")
        run("config", "user.name", "t")
        (self.repo / "app.py").write_text("print('hello')\n")
        run("add", ".")
        run("commit", "-qm", "init")
        self.run = run

    def watcher(self):
        n = Notifier()
        w = secret_watch.SecretWatcher({"enabled": True, "scan_roots": [self.tmp.name], "interval_hours": 0}, n)
        return w, n

    def test_new_secret_is_reported_once_without_leaking_value(self):
        w, n = self.watcher()
        w.check(force=True)
        self.assertEqual(n.alerts, [])  # クリーンな状態では何も出ない
        key = "AKIA" + "ABCDEFGHIJKLMNOP"  # 形式だけ満たすダミー
        (self.repo / "config.py").write_text(f'AWS = "{key}"\n')
        self.run("add", ".")
        self.run("commit", "-qm", "oops")
        w.check(force=True)
        crit = [a for a in n.alerts if a[2] == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertEqual((crit[0][0], crit[0][3]), ("secret_watch", False))
        self.assertIn("aws-access-key", crit[0][1])
        self.assertNotIn(key, crit[0][1])
        self.assertIn("AKIA…", crit[0][1])
        w.check(force=True)  # 2回目は同じものを再通知しない
        self.assertEqual(len([a for a in n.alerts if a[2] == "critical"]), 1)

    def test_secret_removed_but_left_in_history_is_still_detected(self):
        key = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        (self.repo / "t.txt").write_text(f"token={key}\n")
        self.run("add", ".")
        self.run("commit", "-qm", "add")
        self.run("rm", "-q", "t.txt")
        self.run("commit", "-qm", "remove")
        w, n = self.watcher()
        w.check(force=True)
        self.assertTrue([a for a in n.alerts if "github-token" in a[1] and "履歴" not in a[1] or "@" in a[1]])
        self.assertFalse(any(key in a[1] for a in n.alerts))

    def test_world_readable_env_is_warned(self):
        env = self.repo / ".env"
        env.write_text("X=1\n")
        os.chmod(env, 0o644)
        w, n = self.watcher()
        w.check(force=True)
        self.assertTrue([a for a in n.alerts if a[2] == "warning" and "読める権限" in a[1]])
        os.chmod(env, 0o600)
        self.assertEqual(secretscan.permission_findings(str(self.repo)), [])

    def test_unreadable_root_reports_reason_and_retries_in_an_hour(self):
        n = Notifier()
        w = secret_watch.SecretWatcher({"enabled": True, "scan_roots": [str(Path(self.tmp.name) / "nope")], "interval_hours": 24}, n)
        w.check(force=True)
        self.assertEqual(n.alerts[0][2], "error")
        self.assertIn("アクセスできません", n.alerts[0][1])
        self.assertLess(w._state["last_run"] + 24 * 3600 - __import__("time").time(), 3700)  # 次回は約1時間後
        denied = secret_watch.SecretWatcher._access_error([("/Volumes/X", PermissionError(1, "Operation not permitted"))])
        self.assertIn("フルディスクアクセス", denied)

    def test_placeholders_and_url_slugs_are_not_flagged(self):
        line = 'API_KEY = "your-api-key-here-xxxxxxxxxxxxxxxx"'
        self.assertEqual(secretscan.scan_line(line), [])
        self.assertEqual(secretscan.scan_line("https://example.com/sandisk-and-sk-hynix-unveil-hbf-spec-up-to-16-hi-nand-stacks-3-tb-s"), [])


try:
    import fastapi  # noqa: F401
    HAVE_WEBUI = True
except ImportError:
    HAVE_WEBUI = False


@unittest.skipUnless(HAVE_WEBUI, "fastapi未インストール")
class ExposureTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / "webui"))
        import exposure
        self.exposure = exposure
        self.store = {"exposure_enabled": "true", "exposure_ips": "93.184.216.34", "exposure_risky_ports": exposure.DEFAULT_RISKY_PORTS,
                      "exposure_interval_hours": "12"}
        self.sent = []
        self.w = exposure.ExposureWatcher(lambda k: self.store.get(k, ""), lambda k, v: self.store.__setitem__(k, v),
                                          lambda cat, msg, sev, host: self.sent.append((sev, msg)))

    def observe(self, ports, vulns=()):
        return patch.object(self.exposure.ExposureWatcher, "observe", staticmethod(lambda ip: {"ports": ports, "vulns": list(vulns), "hostnames": []}))

    def test_baseline_then_new_port_then_risky_port(self):
        with self.observe([22, 80, 443]):
            self.assertEqual([s for s, _ in self.w.run(force=True)], ["info"])
        with self.observe([22, 80, 443]):
            self.assertEqual(self.w.run(force=True), [])  # 変化なし
        with self.observe([22, 80, 443, 8088]):
            self.assertEqual([s for s, _ in self.w.run(force=True)], ["warning"])
        with self.observe([22, 80, 443, 8088, 3306]):
            r = self.w.run(force=True)
            self.assertEqual([s for s, _ in r], ["critical"])
            self.assertIn("3306", r[0][1])

    def test_risky_port_on_first_observation_and_new_vuln_are_critical(self):
        with self.observe([22, 6379], vulns=["CVE-2024-0001"]):
            r = self.w.run(force=True)
        self.assertEqual(sorted(s for s, _ in r), ["critical", "critical"])
        with self.observe([22, 6379], vulns=["CVE-2024-0001", "CVE-2025-0002"]):
            r = self.w.run(force=True)
        self.assertEqual([s for s, _ in r], ["critical"])
        self.assertIn("CVE-2025-0002", r[0][1])

    def test_disabled_and_interval_and_failure(self):
        self.store["exposure_enabled"] = "false"
        with self.observe([22]):
            self.assertEqual(self.w.run(), [])
        self.store["exposure_enabled"] = "true"
        with self.observe([22]):
            self.w.run(now=1000.0)
            self.assertEqual(self.w.run(now=1000.0 + 3600), [])  # 間隔内は再確認しない
        with patch.object(self.exposure.ExposureWatcher, "observe", staticmethod(lambda ip: None)):
            self.assertEqual(self.w.run(force=True), [])  # 通信失敗は何も通知しない


if __name__ == "__main__":
    unittest.main()
