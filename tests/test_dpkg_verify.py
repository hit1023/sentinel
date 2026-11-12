import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


class DpkgVerifyTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.data = tempfile.mkdtemp()
        os.environ["HITIDS_FS_PREFIX"] = self.root
        os.environ["HITIDS_DATA_DIR"] = self.data
        for m in ("paths", "dpkg_verify", "integrity"):
            sys.modules.pop(m, None)
        import dpkg_verify
        self.dv = dpkg_verify
        os.makedirs(f"{self.root}/var/lib/dpkg/info")
        os.makedirs(f"{self.root}/etc/hp")
        os.makedirs(f"{self.root}/usr/lib")

    def tearDown(self):
        os.environ.pop("HITIDS_FS_PREFIX", None)

    def write(self, rel, data: bytes):
        p = f"{self.root}{rel}"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    def test_conffile_matching_dpkg_status_is_verified(self):
        self.write("/etc/hp/hplip.conf", b"[hplip]\nversion=3.23\n")
        with open(f"{self.root}/var/lib/dpkg/status", "w") as f:
            f.write(f"Package: libsane-hpaio\nConffiles:\n /etc/hp/hplip.conf {md5(b'[hplip]\nversion=3.23\n')}\n\n")
        self.assertEqual(self.dv.verify(["/etc/hp/hplip.conf"]), {"/etc/hp/hplip.conf"})

    def test_conffile_edited_after_install_is_not_verified(self):
        self.write("/etc/hp/hplip.conf", b"backdoor=1\n")
        with open(f"{self.root}/var/lib/dpkg/status", "w") as f:
            f.write(f"Package: libsane-hpaio\nConffiles:\n /etc/hp/hplip.conf {md5(b'[hplip]\n')}\n\n")
        self.assertEqual(self.dv.verify(["/etc/hp/hplip.conf"]), set())

    def test_regular_file_matching_md5sums_is_verified_and_tampered_is_not(self):
        self.write("/usr/lib/libfoo.so", b"genuine")
        self.write("/usr/lib/libbar.so", b"tampered!")
        open(f"{self.root}/var/lib/dpkg/status", "w").close()
        with open(f"{self.root}/var/lib/dpkg/info/libfoo:amd64.md5sums", "w") as f:
            f.write(f"{md5(b'genuine')}  usr/lib/libfoo.so\n{md5(b'original')}  usr/lib/libbar.so\n")
        self.assertEqual(self.dv.verify(["/usr/lib/libfoo.so", "/usr/lib/libbar.so"]), {"/usr/lib/libfoo.so"})

    def test_file_not_owned_by_any_package_is_not_verified(self):
        self.write("/etc/passwd", b"root:x:0:0\n")
        open(f"{self.root}/var/lib/dpkg/status", "w").close()
        self.assertEqual(self.dv.verify(["/etc/passwd"]), set())

    def test_host_without_dpkg_verifies_nothing(self):
        self.write("/etc/hosts", b"127.0.0.1 localhost\n")
        os.remove(f"{self.root}/var/lib/dpkg/info") if False else None
        # statusが無い(macOS等)
        self.assertEqual(self.dv.verify(["/etc/hosts"]), set())


class IntegrityPackageUpdateTest(unittest.TestCase):
    """integrity_watch全体: パッケージ更新による変更はINFO、それ以外の改ざんはCRITICALのまま。"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.data = tempfile.mkdtemp()
        os.environ["HITIDS_FS_PREFIX"] = self.root
        os.environ["HITIDS_DATA_DIR"] = self.data
        for m in ("paths", "dpkg_verify", "integrity"):
            sys.modules.pop(m, None)
        import integrity
        self.integrity = integrity
        os.makedirs(f"{self.root}/etc/hp")
        os.makedirs(f"{self.root}/var/lib/dpkg")
        self.alerts = []

        class N:
            def alert(n, category, message, severity="warning", **kw):
                self.alerts.append((severity, message))

        self.watcher = integrity.IntegrityWatcher(
            {"watch_paths": ["/etc"], "baseline_path": f"{self.data}/b.json"}, N())

    def tearDown(self):
        os.environ.pop("HITIDS_FS_PREFIX", None)

    def set_status(self, conf_md5s: dict):
        lines = "Package: x\nConffiles:\n" + "".join(f" {p} {m}\n" for p, m in conf_md5s.items()) + "\n"
        with open(f"{self.root}/var/lib/dpkg/status", "w") as f:
            f.write(lines)

    def test_package_update_is_info_and_tampering_is_critical(self):
        a, b = f"{self.root}/etc/hp/hplip.conf", f"{self.root}/etc/evil.conf"
        for p in (a, b):
            with open(p, "w") as f:
                f.write("old\n")
        self.set_status({})
        self.watcher.check()  # ベースライン
        self.alerts.clear()
        with open(a, "w") as f:
            f.write("new-from-package\n")
        with open(b, "w") as f:
            f.write("changed-by-attacker\n")
        self.set_status({"/etc/hp/hplip.conf": md5(b"new-from-package\n")})
        self.watcher.check()
        by_msg = {m.split(": ")[-1]: s for s, m in self.alerts}
        self.assertEqual(by_msg[a], "info")
        self.assertEqual(by_msg[b], "critical")
        self.assertTrue(any("dpkg検証済み" in m for s, m in self.alerts))

    def test_ssh_key_change_is_always_critical_even_if_it_looks_verified(self):
        os.makedirs(f"{self.root}/etc/.ssh")
        k = f"{self.root}/etc/.ssh/authorized_keys"
        with open(k, "w") as f:
            f.write("old\n")
        self.watcher.critical_patterns = ["*/.ssh/*"]
        self.set_status({})
        self.watcher.check()
        self.alerts.clear()
        with open(k, "w") as f:
            f.write("ssh-rsa ATTACKER\n")
        self.set_status({"/etc/.ssh/authorized_keys": md5(b"ssh-rsa ATTACKER\n")})
        self.watcher.check()
        self.assertEqual([s for s, _ in self.alerts], ["critical"])


if __name__ == "__main__":
    unittest.main()
