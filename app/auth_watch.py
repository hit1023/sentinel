"""SSH等の認証ログを監視し、ブルートフォースや不正アクセスの兆候を検知する"""
import json
import os
import re
import subprocess
import time
from collections import defaultdict, deque

FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")

STATE_PATH = "/data/auth_watch_state.json"


class AuthWatcher:
    def __init__(self, config: dict, notifier):
        self.config = config
        self.notifier = notifier
        self.fail_threshold = config.get("fail_threshold", 5)
        self.fail_window = config.get("fail_window_seconds", 300)
        self.notify_on_success = config.get("notify_on_success", True)
        self.use_journalctl = config.get("use_journalctl", False)
        self.log_paths = config.get("log_paths", [])
        # ip -> deque[timestamp]
        self._fail_events = defaultdict(deque)
        self._state = self._load_state()

    def _load_state(self):
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        return {"offsets": {}, "journal_cursor": None}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(self._state, f)

    def _iter_new_lines_from_file(self, path):
        if not os.path.exists(path) or not os.path.isfile(path):
            # マウント先が存在しない/ディレクトリの場合（Mac開発環境等）は静かにスキップ
            return
        size = os.path.getsize(path)
        if path not in self._state["offsets"]:
            # 初回はファイル末尾から監視開始（既存の巨大な過去ログを読み込んで
            # 大量通知を出さないため）。過去分を遡って検知したい場合は
            # state/auth_watch_state.json を削除してから0から始めること。
            self._state["offsets"][path] = size
            return
        offset = self._state["offsets"][path]
        if size < offset:
            # ログローテーションで縮小 → 先頭から読み直す
            offset = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for line in f:
                yield line
            self._state["offsets"][path] = f.tell()

    def _iter_new_lines_from_journal(self):
        cursor = self._state.get("journal_cursor")
        cmd = ["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "cat"]
        if cursor:
            cmd += ["--after-cursor", cursor]
        else:
            cmd += ["-n", "0"]  # 初回は過去分をスキップし、以後の差分だけ拾う
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as e:
            self.notifier.alert("auth_watch", f"journalctl実行に失敗: {e}", "error")
            return
        lines = out.stdout.splitlines()
        for line in lines:
            yield line
        # 次回用カーソルを取得
        try:
            cur = subprocess.run(
                ["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", "0", "--show-cursor"],
                capture_output=True, text=True, timeout=15,
            )
            for l in cur.stdout.splitlines():
                if l.startswith("-- cursor:"):
                    self._state["journal_cursor"] = l.split("cursor:", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass

    def _process_line(self, line):
        now = time.time()

        m = FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user")
            dq = self._fail_events[ip]
            dq.append(now)
            while dq and now - dq[0] > self.fail_window:
                dq.popleft()
            if len(dq) == self.fail_threshold:
                self.notifier.alert(
                    "auth_watch",
                    f"ブルートフォースの疑い: {ip} から{self.fail_window}秒間に"
                    f"{self.fail_threshold}回のログイン失敗（直近ユーザー: {user}）",
                    "critical",
                )
            return

        m = INVALID_USER_RE.search(line)
        if m:
            self.notifier.alert(
                "auth_watch",
                f"存在しないユーザーへのログイン試行: user={m.group('user')} from={m.group('ip')}",
                "warning",
            )
            return

        m = ACCEPTED_RE.search(line)
        if m and self.notify_on_success:
            self.notifier.alert(
                "auth_watch",
                f"ログイン成功: user={m.group('user')} from={m.group('ip')} method={m.group('method')}",
                "info",
            )

    def check(self):
        try:
            if self.use_journalctl:
                lines = self._iter_new_lines_from_journal()
            else:
                lines = []
                for path in self.log_paths:
                    lines.extend(self._iter_new_lines_from_file(path))
            for line in lines:
                self._process_line(line)
        finally:
            self._save_state()
