"""SSH等の認証ログを監視し、ブルートフォースや不正アクセスの兆候を検知する"""
import json
import os
import re
import subprocess
import time
from collections import defaultdict, deque

import geoip
import paths

FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")

STATE_PATH = os.path.join(paths.data_dir(), "auth_watch_state.json")


class AuthWatcher:
    def __init__(self, config: dict, notifier):
        self.config = config
        self.notifier = notifier
        self.fail_threshold = config.get("fail_threshold", 5)
        self.fail_window = config.get("fail_window_seconds", 300)
        self.notify_on_success = config.get("notify_on_success", True)
        self.use_journalctl = config.get("use_journalctl", False)
        self.log_paths = [paths.resolve_log_path(p) for p in config.get("log_paths", [])]
        self.sensitive_users = {u.lower() for u in config.get("sensitive_users", [])}
        self.geoip_enabled = config.get("geoip_enabled", True)
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
        return {"offsets": {}, "journal_cursor": None, "known_countries": []}

    def _location_suffix(self, ip: str) -> str:
        if not self.geoip_enabled:
            return ""
        info = geoip.lookup(ip)
        # LAN内からのアクセスや位置情報が取得できなかった場合は、
        # 「location=不明」のようなノイズを出さず何も付けない
        if not info.get("country"):
            return ""
        return f" location={geoip.format_location(info)}"

    def _check_unusual_location(self, ip: str):
        """ログイン成功元の国を記録し、これまで見たことのない国からの成功ログインは
        （侵入経路として最も重大なパターンの一つのため）閾値なしで即CRITICAL通知する。
        初めて起動した直後は既知の国が空なので、最初に見た国は静かにベースライン登録し、
        それ以降に現れた新しい国だけをアラート対象にする（過去分の遡及検知はしない設計と同じ思想）。"""
        if not self.geoip_enabled:
            return None
        info = geoip.lookup(ip)
        country = info.get("country") or ""
        if not country:
            return None
        known = set(self._state.get("known_countries", []))
        if country in known:
            return None
        is_first_ever = len(known) == 0
        known.add(country)
        self._state["known_countries"] = list(known)
        if is_first_ever:
            return None
        return geoip.format_location(info)

    def _is_unusual_location_readonly(self, ip: str):
        """失敗ログイン試行用。_check_unusual_locationと違い、ベースラインへの
        書き込みは一切行わない（攻撃者が失敗を1回混ぜるだけでその国を「既知」に
        されては意味がないため）。ベースライン未確立（起動直後）の間は判定しない。"""
        if not self.geoip_enabled:
            return None
        info = geoip.lookup(ip)
        country = info.get("country") or ""
        if not country:
            return None
        known = set(self._state.get("known_countries", []))
        if not known or country in known:
            return None
        return geoip.format_location(info)

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
            is_invalid_user = m.group(1) is not None  # "invalid user " prefix
            dq = self._fail_events[ip]
            dq.append(now)
            while dq and now - dq[0] > self.fail_window:
                dq.popleft()
            if len(dq) == self.fail_threshold:
                self.notifier.alert(
                    "auth_watch",
                    f"ブルートフォースの疑い: {ip} から{self.fail_window}秒間に"
                    f"{self.fail_threshold}回のログイン失敗（直近ユーザー: {user}）"
                    f"{self._location_suffix(ip)}",
                    "critical",
                )
            # root等のセンシティブなユーザー名は、実在するため「invalid user」判定に
            # ならず、上記の閾値到達までアラートが一切出ない。狙われやすい名前は
            # ブルートフォース閾値を待たず1回目から即座に警告する。
            # (invalid userの場合は下のINVALID_USER_REで既に警告されるため対象外)
            elif not is_invalid_user and user.lower() in self.sensitive_users:
                self.notifier.alert(
                    "auth_watch",
                    f"要注意ユーザーへのログイン失敗: user={user} from={ip}{self._location_suffix(ip)}",
                    "warning",
                )
            else:
                # ブルートフォース閾値未満・要注意ユーザーでもない、通常なら無音になる
                # 失敗試行でも、見慣れない国からであればWARNINGで知らせる
                unusual = self._is_unusual_location_readonly(ip)
                if unusual:
                    self.notifier.alert(
                        "auth_watch",
                        f"見慣れないロケーションからのログイン試行（失敗）: "
                        f"user={user} from={ip} location={unusual}",
                        "warning",
                    )
            return

        m = INVALID_USER_RE.search(line)
        if m:
            ip = m.group("ip")
            self.notifier.alert(
                "auth_watch",
                f"存在しないユーザーへのログイン試行: user={m.group('user')} from={ip}"
                f"{self._location_suffix(ip)}",
                "warning",
            )
            return

        m = ACCEPTED_RE.search(line)
        if m:
            ip = m.group("ip")
            unusual = self._check_unusual_location(ip)
            if unusual:
                self.notifier.alert(
                    "auth_watch",
                    f"いつもと異なるロケーションからのログイン成功: "
                    f"user={m.group('user')} from={ip} method={m.group('method')} "
                    f"location={unusual}",
                    "critical",
                )
            elif self.notify_on_success:
                self.notifier.alert(
                    "auth_watch",
                    f"ログイン成功: user={m.group('user')} from={ip} method={m.group('method')}"
                    f"{self._location_suffix(ip)}",
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
