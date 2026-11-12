import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui"))

import noise_guard  # noqa: E402


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def rec(message, severity="warning", category="procnet_watch", host="h-3"):
    return {"host": host, "category": category, "severity": severity, "message": message,
            "original_severity": None}


class NoiseGuardTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.guard = noise_guard.NoiseGuard(clock=self.clock, budget=5)

    def test_same_content_repeat_is_downgraded_but_first_passes(self):
        first = rec("未知のプロセスを検知: pid=100 name=pipewire cmd=/usr/bin/pipewire")
        again = rec("未知のプロセスを検知: pid=2345 name=pipewire cmd=/usr/bin/pipewire")
        self.assertIsNone(self.guard.apply(first))
        self.assertEqual(first["severity"], "warning")
        self.guard.apply(again)
        self.assertEqual(again["severity"], "info")
        self.assertEqual(again["original_severity"], "warning")
        self.assertEqual(again["noise_guard"], "同じ内容の再発")

    def test_repeat_passes_again_after_window(self):
        self.guard.apply(rec("未知のプロセスを検知: pid=1 name=x"))
        self.clock.now += noise_guard.DEDUPE_WINDOW_SECONDS + 1
        later = rec("未知のプロセスを検知: pid=9 name=x")
        self.guard.apply(later)
        self.assertEqual(later["severity"], "warning")

    def test_different_content_is_not_deduped(self):
        a = rec("未知のプロセスを検知: pid=1 name=aaa")
        b = rec("未知のプロセスを検知: pid=2 name=bbb")
        self.guard.apply(a)
        self.guard.apply(b)
        self.assertEqual((a["severity"], b["severity"]), ("warning", "warning"))

    def test_budget_downgrades_surplus_and_notifies_once_per_hour(self):
        notices = []
        records = []
        for i in range(8):
            r = rec(f"未知のプロセスを検知: pid={i} name=proc{chr(97 + i)}")
            records.append(r)
            n = self.guard.apply(r)
            if n:
                notices.append(n)
        self.assertEqual([r["severity"] for r in records], ["warning"] * 5 + ["info"] * 3)
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["category"], "noise_guard")
        self.assertEqual(notices[0]["severity"], "warning")
        self.assertEqual(notices[0]["host"], "h-3")
        # 1時間後なら、また上限超過時に通知が出る
        self.clock.now += noise_guard.BUDGET_WINDOW_SECONDS + 1
        again = []
        for i in range(8):
            n = self.guard.apply(rec(f"別の内容 {chr(65 + i)}"))
            if n:
                again.append(n)
        self.assertEqual(len(again), 1)

    def test_critical_is_never_touched(self):
        for _ in range(30):
            r = rec("ファイル改ざんの疑い: /etc/passwd", severity="critical", category="integrity_watch")
            self.assertIsNone(self.guard.apply(r))
            self.assertEqual(r["severity"], "critical")

    def test_security_signal_categories_are_not_guarded(self):
        for i in range(30):
            r = rec("SSHログイン失敗 from=203.0.113.9", category="auth_watch")
            self.guard.apply(r)
            self.assertEqual(r["severity"], "warning")

    def test_budget_is_per_host_and_category(self):
        for i in range(5):
            self.guard.apply(rec(f"x{chr(97 + i)}", host="h-3"))
        other_host = rec("xz", host="f-1")
        self.guard.apply(other_host)
        self.assertEqual(other_host["severity"], "warning")


if __name__ == "__main__":
    unittest.main()
