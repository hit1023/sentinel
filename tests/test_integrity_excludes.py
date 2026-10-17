import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


class IntegrityExcludes(unittest.TestCase):
    def test_ld_so_cache_is_always_excluded_even_with_old_config(self):
        os.environ["HITIDS_DATA_DIR"] = tempfile.mkdtemp()
        sys.modules.pop("paths", None)
        import integrity
        # 既存ホストの古いconfig.yaml（ld.so.cacheの記載なし）でも除外される
        w = integrity.IntegrityWatcher({"watch_paths": [], "exclude_patterns": ["*.log"]}, notifier=None)
        self.assertTrue(w._is_excluded("/etc/ld.so.cache"))
        self.assertTrue(w._is_excluded("/hostfs/etc/ld.so.cache"))
        self.assertTrue(w._is_excluded("/var/x.log"))
        self.assertFalse(w._is_excluded("/etc/passwd"))
        self.assertFalse(w._is_excluded("/etc/ld.so.conf"))


if __name__ == "__main__":
    unittest.main()
