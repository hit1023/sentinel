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

# --- ログイン後の権限昇格・永続化の兆候（auth.logのファイル方式で有効。journalctl方式はsshのみ） ---
# syslogの行頭（日時 ホスト名）の直後に来るプロセス名。攻撃者が制御できるユーザー名等の文字列に
# 「useradd: new user: …」のような偽の行を混ぜられても、プロセス名の位置でしか反応しないようにする
SYSLOG_PROC_RE = re.compile(r"^(?:\w{3}\s+\d+\s+[\d:]+|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+(?P<proc>[\w.-]+)(?:\[\d+\])?:")
PRIV_PROCS = {"useradd", "usermod", "gpasswd", "adduser", "su", "sudo", "passwd"}
NEW_USER_RE = re.compile(r"useradd(?:\[\d+\])?: new user: name=(?P<user>[^,\s]+)")
PRIV_GROUPS = "sudo|admin|wheel|root|adm|docker|lxd|shadow"
GROUP_ADD_RE = re.compile(
    rf"(?:usermod|gpasswd|useradd|adduser)(?:\[\d+\])?: .*?(?:add|added) '?(?P<user>[^'\s]+)'? to (?:shadow )?group '?(?P<group>{PRIV_GROUPS})\b",
    re.I,
)
# gpasswd / adduser の形式（Ubuntu: "gpasswd: user bob added by root to group sudo"）
GROUP_ADD2_RE = re.compile(
    rf"user (?P<u1>\S+) added by \S+ to group (?P<g1>{PRIV_GROUPS})\b|Adding user [`'](?P<u2>[^'`\s]+)['`] to group [`'](?P<g2>{PRIV_GROUPS})['`]",
    re.I,
)
SU_ROOT_RE = re.compile(r"su(?:\[\d+\])?: \(to root\) (?P<user>\S+) on|pam_unix\(su(?:-l)?:session\): session opened for user root by (?P<user2>\S+?)\(")
SUDO_FAIL_RE = re.compile(r": (?:user )?(?P<what>NOT in sudoers|\d+ incorrect password attempts?) ;")
PASSWD_CHANGE_RE = re.compile(r"passwd(?:\[\d+\])?: pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)")

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
        # 「失敗の連発 → 同一IPからログイン成功」を侵入成功の疑いとしてCRITICAL通知する
        self.compromise_enabled = config.get("compromise_detection", True)
        self.compromise_window = config.get("compromise_window_seconds", 3600)
        self.compromise_min_failures = config.get("compromise_min_failures", 5)
        # 新規ユーザー作成・sudo権限の付与・su・sudo失敗・パスワード変更（侵入後の足場づくり）
        self.privilege_events = config.get("privilege_events", True)
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
        return {"offsets": {}, "journal_cursor": None, "known_countries": [], "recent_fails": {}}

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

    def _record_failure(self, ip: str, user: str, now: float):
        """侵入成功の相関検知用に、IPごとの失敗ログイン履歴（時刻とユーザー名）を保持する。
        ブルートフォース検知用のfail_window(既定5分)より長い窓で持つ。"""
        history = self._state.setdefault("recent_fails", {})
        entries = history.setdefault(ip, [])
        entries.append([now, user])
        # 1IPあたりの肥大化防止（直近分だけ残す）
        del entries[:-200]

    def _prune_failures(self, now: float):
        history = self._state.setdefault("recent_fails", {})
        for ip in list(history):
            history[ip] = [e for e in history[ip] if now - e[0] <= self.compromise_window]
            if not history[ip]:
                del history[ip]
        # IP数の上限（分散型ブルートフォースで状態ファイルが肥大化しないように）
        if len(history) > 2000:
            newest = sorted(history, key=lambda k: history[k][-1][0], reverse=True)[:2000]
            self._state["recent_fails"] = {k: history[k] for k in newest}

    def _check_compromise(self, ip: str, user: str, method: str, now: float):
        """同一IPからの失敗が窓内にcompromise_min_failures回以上あった後にログインが
        成功した場合、認証突破（侵入成功）の疑いとしてCRITICALを返す。該当しなければFalse。
        一度通知したらそのIPの履歴は消し、同じ攻撃で連続して再通知しない。"""
        if not self.compromise_enabled:
            return False
        history = self._state.setdefault("recent_fails", {})
        entries = [e for e in history.get(ip, []) if now - e[0] <= self.compromise_window]
        if len(entries) < self.compromise_min_failures:
            return False
        tried = sorted({e[1] for e in entries})
        tried_text = ",".join(tried[:5]) + ("…" if len(tried) > 5 else "")
        history.pop(ip, None)
        self.notifier.alert(
            "auth_watch",
            f"侵入成功の疑い: ブルートフォース後にログイン成功: user={user} from={ip} method={method} "
            f"（直前{self.compromise_window // 60}分間に{len(entries)}回失敗、試行ユーザー: {tried_text}）"
            f"{self._location_suffix(ip)}",
            "critical",
            allow_ai_dismiss=False,
        )
        return True

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

    def _check_privilege(self, line) -> bool:
        """ログイン後の権限昇格・永続化の兆候を通知する。該当したらTrue。"""
        if not self.privilege_events:
            return False
        head = SYSLOG_PROC_RE.match(line)
        if not head or head.group("proc") not in PRIV_PROCS:
            return False
        m = NEW_USER_RE.search(line)
        if m:
            self.notifier.alert("auth_watch", f"新規ユーザーが作成されました: user={m.group('user')}（侵入後のバックドア作成の可能性）", "critical", allow_ai_dismiss=False)
            return True
        m = GROUP_ADD_RE.search(line)
        if m:
            self.notifier.alert("auth_watch", f"特権グループへユーザーが追加されました: user={m.group('user')} group={m.group('group')}", "critical", allow_ai_dismiss=False)
            return True
        m = GROUP_ADD2_RE.search(line)
        if m:
            user, group = (m.group("u1"), m.group("g1")) if m.group("u1") else (m.group("u2"), m.group("g2"))
            self.notifier.alert("auth_watch", f"特権グループへユーザーが追加されました: user={user} group={group}", "critical", allow_ai_dismiss=False)
            return True
        m = SU_ROOT_RE.search(line)
        if m:
            who = m.group("user") or m.group("user2")
            self.notifier.alert("auth_watch", f"suでrootに切り替えられました: by={who}", "warning")
            return True
        m = SUDO_FAIL_RE.search(line)
        if m:
            self.notifier.alert("auth_watch", f"sudoの失敗: {m.group('what')}", "warning")
            return True
        m = PASSWD_CHANGE_RE.search(line)
        if m:
            self.notifier.alert("auth_watch", f"パスワードが変更されました: user={m.group('user')}", "warning")
            return True
        return False

    def _process_line(self, line):
        now = time.time()
        if self._check_privilege(line):
            return

        m = FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user")
            is_invalid_user = m.group(1) is not None  # "invalid user " prefix
            self._record_failure(ip, user, now)
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
            # 相関検知が成立した場合は、見慣れない国のCRITICALと二重に出さずこちらに統合する
            # （場所の情報はメッセージ末尾に含まれる）
            if self._check_compromise(ip, m.group("user"), m.group("method"), now):
                return
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
            self._prune_failures(time.time())
            self._save_state()
