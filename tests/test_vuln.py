"""パッケージ収集(app/package_watch.py)と脆弱性照合(webui/vuln.py)のテスト。
OSV/KEVへの通信はモックし、ネットワーク無しで照合・差分アラートの挙動を確認する。"""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "webui"))
import package_watch  # noqa: E402
import vuln  # noqa: E402

DPKG_STATUS = """Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.13-0ubuntu3)
Version: 3.0.13-0ubuntu3
Description: Secure Sockets Layer toolkit
 continuation line: should be ignored

Package: openssl
Status: install ok installed
Version: 3.0.13-0ubuntu3

Package: sudo
Status: install ok installed
Version: 1.9.15p5-3ubuntu5

Package: old-removed
Status: deinstall ok config-files
Version: 1.0
"""


class PackageWatchParseTests(unittest.TestCase):
    def test_groups_binaries_by_source_and_skips_removed(self):
        pkgs = package_watch.parse_dpkg_status(DPKG_STATUS)
        self.assertEqual(
            pkgs,
            [
                {"name": "openssl", "version": "3.0.13-0ubuntu3", "binaries": ["libssl3t64", "openssl"]},
                {"name": "sudo", "version": "1.9.15p5-3ubuntu5", "binaries": ["sudo"]},
            ],
        )

    def test_osv_ecosystem(self):
        lts = package_watch.parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.3 LTS (Noble Numbat)"\n')
        self.assertEqual(package_watch.osv_ecosystem(lts), "Ubuntu:24.04:LTS")
        interim = {"ID": "ubuntu", "VERSION_ID": "25.04", "VERSION": "25.04 (Plucky Puffin)"}
        self.assertEqual(package_watch.osv_ecosystem(interim), "Ubuntu:25.04")
        self.assertEqual(package_watch.osv_ecosystem({"ID": "debian", "VERSION_ID": "12"}), "Debian:12")
        self.assertIsNone(package_watch.osv_ecosystem({"ID": "fedora", "VERSION_ID": "40"}))


ECO = "Ubuntu:24.04:LTS"


def osv_doc(vid, pkg, fixed, priority):
    return {
        "id": vid,
        "modified": "2026-01-01T00:00:00Z",
        "upstream": [vid.replace("UBUNTU-", "")],
        "details": f"{vid} details",
        "severity": [{"type": "Ubuntu", "score": priority}],
        "affected": [{
            "package": {"name": pkg, "ecosystem": ECO},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])}],
            "ecosystem_specific": {"availability": "No subscription required"},
        }],
    }


DOCS = {
    "UBUNTU-CVE-2025-32463": osv_doc("UBUNTU-CVE-2025-32463", "sudo", "1.9.15p5-3ubuntu5.24.04.1", "high"),
    "UBUNTU-CVE-2024-0001": osv_doc("UBUNTU-CVE-2024-0001", "openssl", "3.0.13-0ubuntu3.1", "high"),
    "UBUNTU-CVE-2024-0002": osv_doc("UBUNTU-CVE-2024-0002", "openssl", None, "low"),
}


class FakeOsv:
    """querybatch / vulns / KEV を差し替えるモック。matchesを書き換えて状況を変える。"""

    def __init__(self):
        self.matches = {
            ("sudo", "1.9.15p5-3ubuntu5"): ["UBUNTU-CVE-2025-32463", "USN-7604-1"],
            ("openssl", "3.0.13-0ubuntu3"): ["UBUNTU-CVE-2024-0001", "UBUNTU-CVE-2024-0002"],
        }
        self.kev = ["CVE-2025-32463"]
        self.detail_calls = []

    def __call__(self, url, payload=None, timeout=60):
        if url == vuln.KEV_URL:
            return {"catalogVersion": "test", "vulnerabilities": [{"cveID": c} for c in self.kev]}
        if url == vuln.OSV_QUERYBATCH_URL:
            results = []
            for q in payload["queries"]:
                ids = self.matches.get((q["package"]["name"], q["version"]), [])
                results.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]})
            return {"results": results}
        vid = url.rsplit("/", 1)[1]
        self.detail_calls.append(vid)
        return DOCS[vid]


class VulnScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "t.db")
        self.settings = {}
        self.alerts = []

        def connect():
            conn = sqlite3.connect(self.db)
            conn.row_factory = sqlite3.Row
            return conn

        self.scanner = vuln.VulnScanner(
            connect,
            lambda cat, msg, sev, host: self.alerts.append((sev, msg)),
            lambda k: self.settings.get(k, ""),
            lambda k, v: self.settings.__setitem__(k, v),
        )
        self.osv = FakeOsv()
        patcher = patch.object(vuln, "_http_json", self.osv)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def send(self, packages, inv_hash):
        changed = self.scanner.store_inventory(
            {"host": "h-1", "ecosystem": ECO, "os": {}, "packages": packages, "inventory_hash": inv_hash}
        )
        self.scanner.run_due()
        return changed

    def test_first_scan_summarizes_and_flags_kev(self):
        self.send(
            [{"name": "sudo", "version": "1.9.15p5-3ubuntu5"}, {"name": "openssl", "version": "3.0.13-0ubuntu3"}],
            "a",
        )
        summary = self.scanner.summary()
        # USN-*はUBUNTU-CVE-*と重複するため除外され、3件になる
        self.assertEqual(summary["hosts"][0]["total"], 3)
        self.assertEqual(summary["hosts"][0]["kev"], 1)
        top = summary["findings"][0]
        self.assertEqual((top["cve"], top["in_kev"], top["fixed_version"]),
                         ("CVE-2025-32463", 1, "1.9.15p5-3ubuntu5.24.04.1"))
        # 初回はサマリー(warning) + KEVまとめ(critical)の2件だけ
        self.assertEqual([s for s, _ in self.alerts], ["warning", "critical"])

    def test_upgrade_resolves_and_new_high_alerts(self):
        self.send([{"name": "sudo", "version": "1.9.15p5-3ubuntu5"}], "a")
        self.alerts.clear()
        # sudoを修正版に上げ、同時にopensslが新規導入された
        self.osv.matches[("sudo", "1.9.15p5-3ubuntu5.24.04.1")] = []
        changed = self.send(
            [{"name": "sudo", "version": "1.9.15p5-3ubuntu5.24.04.1"}, {"name": "openssl", "version": "3.0.13-0ubuntu3"}],
            "b",
        )
        self.assertTrue(changed)
        sev_msgs = sorted(self.alerts)
        # high+修正版ありのopenssl CVEだけwarning、lowの未修正は通知しない、sudoの解消はinfo
        self.assertEqual([s for s, _ in sev_msgs], ["info", "warning"])
        self.assertIn("CVE-2024-0001", sev_msgs[1][1])

    def test_kev_addition_later_raises_critical(self):
        self.osv.kev = []
        self.send([{"name": "openssl", "version": "3.0.13-0ubuntu3"}], "a")
        self.alerts.clear()
        self.osv.kev = ["CVE-2024-0002"]
        self.scanner.run_due(force=True)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0][0], "critical")
        self.assertIn("CVE-2024-0002", self.alerts[0][1])

    def test_details_are_cached(self):
        self.send([{"name": "openssl", "version": "3.0.13-0ubuntu3"}], "a")
        first = len(self.osv.detail_calls)
        self.scanner.run_due(force=True)
        self.assertEqual(len(self.osv.detail_calls), first)

    def test_bulk_package_only_fetches_kev_details(self):
        many = [f"UBUNTU-CVE-2024-{1000 + i}" for i in range(vuln.BULK_THRESHOLD + 5)]
        self.osv.matches[("linux", "6.8.0-31.31")] = many
        kev_id = many[3]
        DOCS[kev_id] = osv_doc(kev_id, "linux", "6.8.0-44.44", "high")
        self.addCleanup(DOCS.pop, kev_id)
        self.osv.kev = [kev_id.replace("UBUNTU-", "")]
        self.send([{"name": "linux", "version": "6.8.0-31.31"}], "a")
        self.assertEqual(self.osv.detail_calls, [kev_id])
        host = self.scanner.summary()["hosts"][0]
        self.assertEqual(host["bulk"][0]["count"], len(many))
        self.assertEqual(host["kev"], 1)

    def test_same_cve_on_two_installed_versions_keeps_both(self):
        self.osv.matches[("linux-hwe-6.8", "6.8.0-124.124")] = ["UBUNTU-CVE-2024-0001"]
        self.osv.matches[("linux-hwe-6.8", "6.8.0-138.138")] = ["UBUNTU-CVE-2024-0001"]
        self.send([{"name": "linux-hwe-6.8", "version": "6.8.0-124.124"},
                   {"name": "linux-hwe-6.8", "version": "6.8.0-138.138"}], "a")
        versions = sorted(f["installed_version"] for f in self.scanner.summary()["findings"])
        self.assertEqual(versions, ["6.8.0-124.124", "6.8.0-138.138"])

    def test_migrates_old_findings_table_without_realerting(self):
        conn = sqlite3.connect(self.db)
        conn.execute("DROP TABLE host_findings")
        conn.execute("""CREATE TABLE host_findings (host TEXT NOT NULL, vuln_id TEXT NOT NULL,
            package TEXT NOT NULL, installed_version TEXT, fixed_version TEXT, availability TEXT,
            cve TEXT, priority TEXT, in_kev INTEGER DEFAULT 0, first_seen REAL, last_seen REAL,
            PRIMARY KEY (host, vuln_id, package))""")
        conn.commit()
        conn.close()
        self.send([{"name": "sudo", "version": "1.9.15p5-3ubuntu5"}], "a")
        conn = sqlite3.connect(self.db)
        conn.execute("DROP TABLE host_findings")
        conn.execute("""CREATE TABLE host_findings (host TEXT NOT NULL, vuln_id TEXT NOT NULL,
            package TEXT NOT NULL, installed_version TEXT, fixed_version TEXT, availability TEXT,
            cve TEXT, priority TEXT, in_kev INTEGER DEFAULT 0, first_seen REAL, last_seen REAL,
            PRIMARY KEY (host, vuln_id, package))""")
        conn.execute("INSERT INTO host_findings VALUES ('h-1','UBUNTU-CVE-2025-32463','sudo',"
                     "'1.9.15p5-3ubuntu5','1.9.15p5-3ubuntu5.24.04.1','x','CVE-2025-32463','high',1,1,1)")
        conn.commit()
        conn.close()
        self.setUp_scanner_again()
        self.alerts.clear()
        self.scanner.run_due(force=True)
        self.assertEqual(self.alerts, [])  # 移行で行が保たれ、既存KEVが「新規」として再通知されない

    def setUp_scanner_again(self):
        def connect():
            conn = sqlite3.connect(self.db)
            conn.row_factory = sqlite3.Row
            return conn
        self.scanner = vuln.VulnScanner(
            connect,
            lambda cat, msg, sev, host: self.alerts.append((sev, msg)),
            lambda k: self.settings.get(k, ""),
            lambda k, v: self.settings.__setitem__(k, v),
        )

    def test_crossing_bulk_threshold_is_not_reported_as_resolved(self):
        ids = [f"UBUNTU-CVE-2024-{2000 + i}" for i in range(vuln.BULK_THRESHOLD)]
        for vid in ids:
            DOCS[vid] = osv_doc(vid, "mozjs91", None, "medium")
        self.addCleanup(lambda: [DOCS.pop(v, None) for v in ids])
        self.osv.kev = []
        self.osv.matches = {("mozjs91", "91.10"): ids}
        self.send([{"name": "mozjs91", "version": "91.10"}], "a")
        self.alerts.clear()
        # OSV側で件数が増えて閾値を超え、件数のみ集計に切り替わった
        self.osv.matches[("mozjs91", "91.10")] = ids + ["UBUNTU-CVE-2024-9999"]
        self.scanner.run_due(force=True)
        self.assertEqual(self.alerts, [])
        self.assertEqual(self.scanner.summary()["hosts"][0]["bulk"][0]["count"], len(ids) + 1)

    def test_inventory_arriving_during_scan_is_not_dropped(self):
        # 照合中(ロック保持中)に届いた依頼は、実行中の側が拾って処理する
        self.scanner.lock.acquire()
        self.scanner.store_inventory(
            {"host": "h-1", "ecosystem": ECO, "packages": [{"name": "sudo", "version": "1.9.15p5-3ubuntu5"}],
             "inventory_hash": "a"}
        )
        self.scanner.run_due()  # ロック取得できず即return
        self.assertIsNone(self.scanner.summary()["hosts"][0]["scanned_at"])
        self.scanner.lock.release()
        self.scanner.run_due()
        self.assertIsNotNone(self.scanner.summary()["hosts"][0]["scanned_at"])


class RemediationTests(unittest.TestCase):
    def finding(self, package, fixed=None, availability=None, in_kev=0, version="1"):
        return {"package": package, "installed_version": version, "fixed_version": fixed,
                "availability": availability, "in_kev": in_kev}

    def test_fix_available_upgrades_installed_binaries(self):
        r = vuln.remediation(self.finding("openssl", "2", "No subscription required"), ["libssl3t64", "openssl"], None)
        self.assertEqual(r["key"], "upgrade")
        self.assertIn("sudo apt update && sudo apt install --only-upgrade libssl3t64 openssl", [s.get("command") for s in r["steps"]])
        # needrestartが無い環境でもエラーにならないよう存在確認してから使う
        self.assertTrue(any((s.get("command") or "").startswith("if command -v needrestart") for s in r["steps"]))

    def test_pro_only_fix(self):
        r = vuln.remediation(self.finding("openssl", "2", "Available with Ubuntu Pro"), ["openssl"], None)
        self.assertEqual(r["key"], "upgrade_pro")
        self.assertTrue(any("pro attach" in (s.get("command") or "") for s in r["steps"]))

    def test_installed_but_not_running_kernel_is_removed(self):
        bins = ["linux-image-6.8.0-31-generic", "linux-modules-6.8.0-31-generic"]
        r = vuln.remediation(self.finding("linux", None, in_kev=1, version="6.8.0-31.31"), bins, "6.8.0-138-generic")
        self.assertEqual(r["key"], "remove")
        self.assertTrue(any("KEV" in n for n in r["notes"]))

    def test_newer_kernel_waiting_for_reboot_is_never_removed(self):
        # gateで実際に起きたケース: 138を導入済みだが124で稼働中（再起動待ち）
        bins = ["linux-image-6.8.0-138-generic", "linux-modules-6.8.0-138-generic"]
        r = vuln.remediation(self.finding("linux-hwe-6.8", version="6.8.0-138.138~22.04.1"),
                             bins, "6.8.0-124-generic")
        self.assertEqual(r["key"], "reboot")
        self.assertFalse(any("remove" in (s.get("command") or "") for s in r["steps"]))

    def test_running_kernel_mentions_pending_newer_kernel(self):
        bins = ["linux-image-6.8.0-124-generic"]
        r = vuln.remediation(self.finding("linux-hwe-6.8", version="6.8.0-124.124~22.04.1"), bins,
                             "6.8.0-124-generic", [(6, 8, 0, 124), (6, 8, 0, 138)])
        self.assertEqual(r["label"], "修正待ち（稼働中カーネル）")
        self.assertTrue(any("6.8.0-138" in n for n in r["notes"]))

    def test_running_kernel_with_fix_needs_reboot(self):
        bins = ["linux-image-6.8.0-31-generic"]
        r = vuln.remediation(self.finding("linux", "6.8.0-44.44"), bins, "6.8.0-31-generic")
        self.assertEqual(r["label"], "カーネル更新+再起動")
        self.assertIn("sudo reboot", [s.get("command") for s in r["steps"]])

    def test_running_kernel_without_fix_waits(self):
        r = vuln.remediation(self.finding("linux"), ["linux-image-6.8.0-31-generic"], "6.8.0-31-generic")
        self.assertEqual(r["label"], "修正待ち（稼働中カーネル）")

    def test_kernel_headers_only_is_not_actionable(self):
        r = vuln.remediation(self.finding("linux", in_kev=1), ["linux-libc-dev"], "6.8.0-138-generic")
        self.assertEqual(r["key"], "none")

    def test_unfixed_library_suggests_checking_dependents(self):
        r = vuln.remediation(self.finding("mozjs91"), ["libmozjs-91-0"], None)
        self.assertEqual(r["label"], "修正待ち：不要なら削除")
        self.assertIn("apt-cache rdepends --installed libmozjs-91-0", [s.get("command") for s in r["steps"]])


if __name__ == "__main__":
    unittest.main()
