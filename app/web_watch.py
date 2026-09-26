"""Nginx / Nginx Proxy Manager access logs: detect reconnaissance and auth probing."""
import glob
import ipaddress
import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote, urlsplit

import paths


STATE_PATH = os.path.join(paths.data_dir(), "web_watch_state.json")
COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^]]+)\] "(?P<method>\S+) (?P<target>\S+) [^\"]+" (?P<status>\d{3})\b'
)
NPM = re.compile(
    r'^\[(?P<date>[^]]+)\] \S+ \S+ (?P<status>\d{3}) - '
    r'(?P<method>\S+) \S+ (?P<host>\S+) "(?P<target>[^"]+)" '
    r'\[Client (?P<ip>[^]]+)\]'
)
SENSITIVE = re.compile(
    r'(^|/)(\.env(?:\.|/|$)|\.git(?:/|$)|\.svn(?:/|$)|wp-admin(?:/|$)|'
    r'wp-login\.php$|phpmyadmin(?:/|$)|adminer(?:\.php|/|$)|'
    r'vendor/phpunit|cgi-bin(?:/|$)|actuator(?:/|$)|server-status$|'
    r'config\.php$|\.aws(?:/|$))', re.I
)
LOGIN = re.compile(r'(^|/)(login|signin|sign-in|wp-login\.php|auth|session)(/|\.|$)', re.I)
TRAVERSAL = re.compile(r'(^|[=/])\.\.(?:/|\\)')


def parse_line(line):
    """Use only the IP recorded by the proxy, never a client-supplied forwarded header."""
    match = NPM.match(line) or COMMON.match(line)
    if not match:
        return None
    data = match.groupdict()
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
        timestamp = datetime.strptime(data["date"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
        status = int(data["status"])
        target = data["target"]
        decoded = unquote(target).lower()
        path = unquote(urlsplit(target).path).lower()
        traversal = bool(TRAVERSAL.search(decoded))
    except (ValueError, OverflowError):
        return None
    if not path.startswith("/"):
        return None
    return timestamp, ip, data.get("host") or "", path, status, traversal


class WebWatcher:
    def __init__(self, config: dict, notifier):
        self.notifier = notifier
        configured = os.environ.get("WEB_LOG_PATHS", "")
        patterns = [p.strip() for p in configured.split(",") if p.strip()] if configured else config.get("log_paths", [])
        self.log_paths = [paths.resolve_fs_path(p) for p in patterns]
        self.window = int(config.get("window_seconds", 300))
        self.scan_threshold = int(config.get("scan_distinct_paths", 5))
        self.auth_threshold = int(config.get("auth_failures", 10))
        self.not_found_threshold = int(config.get("not_found_distinct_paths", 30))
        self.cooldown = int(config.get("alert_cooldown_seconds", 900))
        self._state = self._load_state()
        self._events = defaultdict(deque)
        self._last_alert = {}
        self._missing_reported = False

    def _load_state(self):
        try:
            with open(STATE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"files": {}}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f)
        os.replace(tmp, STATE_PATH)

    def _iter_lines(self, path):
        st = os.stat(path)
        previous = self._state["files"].get(path)
        if previous is None:
            # Initial installation starts at EOF, avoiding alerts on historical traffic.
            self._state["files"][path] = {"inode": st.st_ino, "offset": st.st_size}
            return
        offset = previous["offset"] if previous["inode"] == st.st_ino and st.st_size >= previous["offset"] else 0
        with open(path, "rb") as f:
            f.seek(offset)
            while True:
                position = f.tell()
                line = f.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    f.seek(position)
                    break  # keep partial line for the next poll
                yield line.decode("utf-8", errors="replace")
            self._state["files"][path] = {"inode": os.fstat(f.fileno()).st_ino, "offset": f.tell()}

    def _alert(self, ip, rule, count, timestamp):
        key = (ip, rule)
        if timestamp - self._last_alert.get(key, float("-inf")) < self.cooldown:
            return
        self._last_alert[key] = timestamp
        label = {"scan": "機密・管理パスの探索", "auth": "認証画面への連続失敗", "404": "多数の未存在パスへのアクセス", "traversal": "パスの境界越えを試行"}[rule]
        self.notifier.alert("web_watch", f"Webアクセス異常: {label} ip={ip} 件数={count} 期間={self.window}秒", "warning")

    def _process(self, event):
        timestamp, ip, host, path, status, traversal = event
        events = self._events[ip]
        events.append((timestamp, host, path, status, traversal))
        while events and timestamp - events[0][0] > self.window:
            events.popleft()
        if len(events) > 1000:
            events.popleft()
        scan = {(h, p) for _, h, p, _, _ in events if SENSITIVE.search(p)}
        auth = sum(1 for _, _, p, s, _ in events if LOGIN.search(p) and s in (401, 403, 429))
        not_found = {(h, p) for _, h, p, s, _ in events if s == 404}
        if traversal:
            self._alert(ip, "traversal", 1, timestamp)
        if len(scan) >= self.scan_threshold:
            self._alert(ip, "scan", len(scan), timestamp)
        if auth >= self.auth_threshold:
            self._alert(ip, "auth", auth, timestamp)
        if len(not_found) >= self.not_found_threshold:
            self._alert(ip, "404", len(not_found), timestamp)

    def check(self):
        found = set()
        for pattern in self.log_paths:
            for path in glob.glob(pattern):
                if not os.path.isfile(path) or path in found:
                    continue
                found.add(path)
                try:
                    for line in self._iter_lines(path):
                        event = parse_line(line)
                        if event:
                            self._process(event)
                except OSError as e:
                    self.notifier.alert("web_watch", f"Webログを読み取れません: {path}: {e}", "error")
        if self.log_paths and not found and not self._missing_reported:
            self.notifier.alert("web_watch", "Webログが見つかりません。WEB_LOG_PATHSと読み取り権限を確認してください", "error")
            self._missing_reported = True
        elif found:
            self._missing_reported = False
        self._state["files"] = {p: v for p, v in self._state["files"].items() if p in found}
        self._save_state()
        # Keep idle client state bounded on long-running agents.
        cutoff = time.time() - self.window
        for ip in list(self._events):
            if not self._events[ip] or self._events[ip][-1][0] < cutoff:
                del self._events[ip]
        for key, last in list(self._last_alert.items()):
            if last < time.time() - self.cooldown:
                del self._last_alert[key]
