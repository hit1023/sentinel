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
    r'(?: \S+ "[^"]*" "(?P<ua>[^"]*)")?'
)
NPM = re.compile(
    r'^\[(?P<date>[^]]+)\] \S+ \S+ (?P<status>\d{3}) - '
    r'(?P<method>\S+) \S+ (?P<host>\S+) "(?P<target>[^"]+)" '
    r'\[Client (?P<ip>[^]]+)\]'
    r'(?:.*?\[Sent-to [^\]]*\] "(?P<ua>[^"]*)")?'
)
SENSITIVE = re.compile(
    r'(^|/)(\.env(?:\.|/|$)|\.git(?:/|$)|\.svn(?:/|$)|wp-admin(?:/|$)|'
    r'wp-login\.php$|phpmyadmin(?:/|$)|adminer(?:\.php|/|$)|'
    r'vendor/phpunit|cgi-bin(?:/|$)|actuator(?:/|$)|server-status$|'
    r'config\.php$|\.aws(?:/|$))', re.I
)
LOGIN = re.compile(r'(^|/)(login|signin|sign-in|wp-login\.php|auth|session)(/|\.|$)', re.I)
TRAVERSAL = re.compile(r'(^|[=/])\.\.(?:/|\\)')

# 攻撃ペイロードの種別（デコード後のURL全体に対して照合。アラートには種別名だけを載せ、
# 攻撃者が制御できるURL本体は載せない）
PAYLOADS = {
    "SQLi": re.compile(
        r"(union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select|information_schema|"
        r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|sleep\(\s*\d+\s*\)|benchmark\(|"
        r"waitfor\s+delay|;\s*drop\s+table|'\s*or\s*'1'\s*=\s*'1)"),
    "XSS": re.compile(r"(<\s*script|javascript:|\bonerror\s*=|\bonload\s*=)"),
    "Log4Shell": re.compile(r"\$\{\s*(jndi|\$\{|env:|lower:|upper:)"),
    "RCE": re.compile(
        r"((;|\||`|\$\(|&&)\s*(wget|curl|bash|sh|nc|ncat|python3?|perl|php|powershell|cmd|whoami|uname)\b|"
        r"/bin/(ba)?sh|cmd\.exe|\beval\s*\(|base64_decode|php://(input|filter)|allow_url_include|"
        r"auto_prepend_file|\$\{.{0,20}runtime)"),
    "LFI": re.compile(r"(/etc/(passwd|shadow|hosts)|/proc/self/|boot\.ini|win\.ini|windows\\system32)"),
}
# 既知の脆弱性スキャナ・攻撃ツール。python-requests/curl等は正規の自動化にも使われるため含めない
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|wfuzz|wpscan|acunetix|nessus|"
    r"openvas|burpsuite|havij|hydra|metasploit|\(\)\s*\{\s*:;\s*\}\s*;)", re.I)
# サーバー側スクリプト（Webシェル設置・探索の定番）。リバースプロキシ配下のアプリが
# PHP等を使わない環境では、これへの要求自体が探索と見なせる
SCRIPT_EXT = re.compile(r"\.(php[0-9]?|phtml|asp|aspx|jsp|jspx|cgi|pl)$", re.I)
# 成功応答(2xx)が返ったら「攻撃が通った可能性」とみなす、特に危険なパス
STRICT_SENSITIVE = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?$|\.git(/|$)|\.aws(/|$)|\.svn(/|$)|\.htpasswd$|wp-config\.php|web\.config$|"
    r"config\.php$|phpinfo\.php$|vendor/phpunit|actuator/(env|heapdump)|server-status$|id_rsa)", re.I)
HOST_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def parse_event(line):
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
        full = unquote(decoded)  # 二重エンコードも展開して照合する
        path = unquote(urlsplit(target).path).lower()
        traversal = bool(TRAVERSAL.search(decoded))
    except (ValueError, OverflowError):
        return None
    if not path.startswith("/"):
        return None
    return {
        "ts": timestamp, "ip": ip, "host": data.get("host") or "", "path": path, "status": status,
        "traversal": traversal, "full": full, "ua": data.get("ua") or "",
    }


def parse_line(line):
    e = parse_event(line)
    if e is None:
        return None
    return e["ts"], e["ip"], e["host"], e["path"], e["status"], e["traversal"]


def payload_kinds(full):
    return [name for name, rx in PAYLOADS.items() if rx.search(full)]


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
        self.script_threshold = int(config.get("script_probe_paths", 4))
        # 新しい検知（ペイロード/スキャナ/スクリプト探索/成功応答）の対象外にするクライアント・ホスト
        self.ignore_private = bool(config.get("ignore_private_ips", True))
        self.script_hosts = {h.strip().lower() for h in config.get("script_hosts", []) if h}
        self.success_critical = bool(config.get("success_critical", True))
        self._state = self._load_state()
        # ホストごとの「未存在パスに404を返した」最終時刻。404を返すサイトでだけ、機密パスへの
        # 200を「攻撃が通った」とみなす（どのパスにも200を返すSPAでの誤検知を避けるため）
        self._state.setdefault("hosts_404", {})
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

    LABELS = {
        "scan": "機密・管理パスの探索", "auth": "認証画面への連続失敗", "404": "多数の未存在パスへのアクセス",
        "traversal": "パスの境界越えを試行", "payload": "攻撃ペイロードを含むリクエスト",
        "scanner": "既知の脆弱性スキャナによるアクセス", "script": "スクリプト・Webシェルの探索",
        "success": "不審なリクエストに成功応答（攻撃が通った可能性）",
    }

    def _alert(self, ip, rule, count, timestamp, detail="", severity="warning"):
        key = (ip, rule)
        if timestamp - self._last_alert.get(key, float("-inf")) < self.cooldown:
            return
        self._last_alert[key] = timestamp
        msg = f"Webアクセス異常: {self.LABELS[rule]} ip={ip} 件数={count} 期間={self.window}秒"
        if detail:
            msg += f" {detail}"
        self.notifier.alert("web_watch", msg, severity)

    def _is_ignored_client(self, ip):
        if not self.ignore_private:
            return False
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local

    def _process(self, event):
        if isinstance(event, tuple):  # 旧形式(6要素)との互換
            ts, ip, host, path, status, traversal = event
            event = {"ts": ts, "ip": ip, "host": host, "path": path, "status": status,
                     "traversal": traversal, "full": path, "ua": ""}
        timestamp, ip, host, path = event["ts"], event["ip"], event["host"], event["path"]
        status, traversal = event["status"], event["traversal"]
        events = self._events[ip]
        events.append((timestamp, host, path, status, traversal))
        while events and timestamp - events[0][0] > self.window:
            events.popleft()
        if len(events) > 1000:
            events.popleft()
        if status == 404:
            self._state["hosts_404"][host] = timestamp
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
        if self._is_ignored_client(ip):
            return
        safe_host = HOST_SAFE.sub("", host)[:80]
        host_tag = f"host={safe_host}" if safe_host else ""
        script_host = host.lower() in self.script_hosts
        kinds = payload_kinds(event["full"])
        if kinds:
            self._alert(ip, "payload", 1, timestamp, f"{host_tag} 種別={','.join(kinds)}".strip())
        if SCANNER_UA.search(event["ua"]):
            self._alert(ip, "scanner", 1, timestamp, host_tag)
        scripts = {(h, p) for _, h, p, _, _ in events if SCRIPT_EXT.search(p) and h.lower() not in self.script_hosts}
        if len(scripts) >= self.script_threshold:
            self._alert(ip, "script", len(scripts), timestamp, host_tag)
        # 成功応答: 他のパスには404を返すサイトで、機密パス自体・スクリプトのパス自体に2xxが返った。
        # ペイロードがクエリに入っていただけのリクエストは、アプリがクエリを無視して通常のページを
        # 返しただけのことが多い（実例: /?payload=${jndi:...} がトップページを返した）ため対象にしない
        suspicious = (bool(STRICT_SENSITIVE.search(path))
                      or (bool(SCRIPT_EXT.search(path)) and not script_host))
        if (self.success_critical and suspicious and 200 <= status < 300
                and timestamp - self._state["hosts_404"].get(host, float("-inf")) <= 7 * 86400):
            self._alert(ip, "success", 1, timestamp, host_tag, severity="critical")

    def check(self):
        found = set()
        for pattern in self.log_paths:
            for path in glob.glob(pattern):
                if not os.path.isfile(path) or path in found:
                    continue
                found.add(path)
                try:
                    for line in self._iter_lines(path):
                        event = parse_event(line)
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
        horizon = time.time() - 7 * 86400
        self._state["hosts_404"] = {h: t for h, t in self._state["hosts_404"].items() if t >= horizon}
        self._save_state()
        # Keep idle client state bounded on long-running agents.
        cutoff = time.time() - self.window
        for ip in list(self._events):
            if not self._events[ip] or self._events[ip][-1][0] < cutoff:
                del self._events[ip]
        for key, last in list(self._last_alert.items()):
            if last < time.time() - self.cooldown:
                del self._last_alert[key]
