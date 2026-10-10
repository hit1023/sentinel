"""リポジトリ内の秘密情報（APIキー・トークン・秘密鍵・パスワード付きURL等）の走査ロジック。

エージェントの secret_watch と、CLI(tools/secret_scan.py)で共有する。
見つけた値そのものは持ち出さず、先頭4文字と長さ（preview）と値のハッシュ（key）だけを扱う。
"""
import hashlib
import os
import re
import shutil
import subprocess

RULES = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack(?:-gov)?\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}")),
    ("discord-webhook", re.compile(r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[\w-]{20,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    # 長いURLスラッグ(sk-hynix-...)と区別するため、新形式のプレフィックスか旧形式の固定部(T3BlbkFJ)を要求する
    ("openai-key", re.compile(r"\b(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url-with-password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"<>]+:([^/\s:@'\"<>$\{]{6,})@(?!localhost|127\.|example)")),
]
# 代入形式の汎用ルール（誤検知が多いので、プレースホルダらしい値は除外する）
GENERIC = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|passwd|password|passphrase|private[_-]?key|auth[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{16,})["']"""
)
PLACEHOLDER = re.compile(
    r"(?i)(xxx|example|changeme|change_me|your[_-]|<.*>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|dummy|sample|placeholder|"
    r"redacted|\*{4}|\.{4}|test|fake|secret_key_here|todo)"
)
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", ".next", "site-packages"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".woff", ".woff2",
            ".ttf", ".mp3", ".mp4", ".wav", ".onnx", ".pt", ".bin", ".safetensors", ".parquet", ".sqlite", ".db", ".lock", ".map", ".min.js"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum"}
MAX_FILE = 1_000_000
MAX_LINE = 2000


def redact(value: str) -> str:
    return f"{value[:4]}…({len(value)}文字)"


def scan_line(line: str):
    """(rule, value) のリストを返す。"""
    if len(line) > MAX_LINE:
        return []
    out = []
    for name, rx in RULES:
        for m in rx.finditer(line):
            value = m.group(1) if name == "url-with-password" else m.group(0)
            if name == "url-with-password" and PLACEHOLDER.search(value):
                continue
            out.append((name, value))
    for m in GENERIC.finditer(line):
        value = m.group(1)
        if PLACEHOLDER.search(value) or len(set(value)) < 6:
            continue
        out.append(("generic-secret", value))
    return out


class Finder:
    def __init__(self, repo):
        self.repo = repo
        self.seen = set()
        self.findings = []

    def add(self, scope, path, rule, value, commit="", line=0):
        key = (path, rule, hashlib.sha256(value.encode()).hexdigest()[:16])
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append({"repo": os.path.basename(self.repo), "scope": scope, "path": path, "rule": rule,
                              "commit": commit, "line": line, "preview": redact(value),
                              "key": f"{os.path.basename(self.repo)}|{scope}|{path}|{rule}|{key[2]}"})


HAVE_GIT = shutil.which("git") is not None


def git(repo, *args, text=True):
    # 他ユーザー所有のリポジトリ（Dockerのbind mount等）でも読めるよう、safe.directoryを許可する
    try:
        return subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, *args], capture_output=True, text=text,
                              errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(args, 1, "" if text else b"", "")


def is_skipped(path: str) -> bool:
    parts = path.split("/")
    base = parts[-1]
    if any(p in SKIP_DIRS for p in parts[:-1]) or base in SKIP_FILES:
        return True
    return os.path.splitext(base)[1].lower() in SKIP_EXT or base.endswith(".min.js")


def _walk_files(repo):
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.relpath(os.path.join(dirpath, fn), repo)


def scan_tree(repo, finder):
    out = git(repo, "ls-files", "-co", "--exclude-standard").stdout.splitlines() if HAVE_GIT else []
    if not out:
        out = list(_walk_files(repo))
    for rel in out:
        if is_skipped(rel):
            continue
        full = os.path.join(repo, rel)
        try:
            if os.path.getsize(full) > MAX_FILE:
                continue
            with open(full, "r", encoding="utf-8", errors="strict") as f:
                for n, line in enumerate(f, 1):
                    for rule, value in scan_line(line):
                        finder.add("作業ツリー", rel, rule, value, line=n)
        except (OSError, UnicodeDecodeError):
            continue


def tracked_env_files(repo):
    if not HAVE_GIT:
        return []
    """.envのようなファイルがgit管理下（履歴含む）にあるか。値は見ず、存在だけを報告する。"""
    names = git(repo, "log", "--all", "--name-only", "--pretty=format:").stdout.splitlines()
    hits = sorted({n for n in names if re.search(r"(^|/)\.env(\.[\w.-]+)?$", n) and not n.endswith((".example", ".sample", ".template"))})
    return hits


def scan_history(repo, finder):
    if not HAVE_GIT:
        return
    proc = subprocess.Popen(["git", "-c", "safe.directory=*", "-C", repo, "log", "--all", "-p", "-U0", "--no-color", "--diff-filter=AM", "--no-merges",
                             "--pretty=format:@@@%h"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    commit, path = "", ""
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.startswith("@@@"):
                commit = line[3:]
            elif line.startswith("+++ b/"):
                path = line[6:]
            elif line.startswith("+") and not line.startswith("+++") and path and not is_skipped(path):
                for rule, value in scan_line(line[1:]):
                    finder.add("履歴", path, rule, value, commit=commit)
    finally:
        proc.stdout.close()
        proc.wait()


# 高信頼（実在するサービスのキー形式）。新規に見つかったらCRITICAL、それ以外はWARNING
HIGH_CONFIDENCE = {
    "aws-access-key", "github-token", "slack-token", "slack-webhook", "discord-webhook", "private-key",
    "google-api-key", "stripe-live-key", "anthropic-key", "openai-key",
}

# 他ユーザーに読めてはいけない秘密情報ファイルの名前
SECRET_FILE_RE = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|.*\.pem|.*\.p12|.*\.pfx|\.netrc|\.pgpass|credentials)$", re.I)
EXAMPLE_RE = re.compile(r"\.(example|sample|template|dist)$|\.pub$", re.I)


def find_repos(root):
    """rootがgitリポジトリならそれ、そうでなければ直下のgitリポジトリを返す。"""
    if not os.path.isdir(root):
        return []
    if os.path.exists(os.path.join(root, ".git")):
        return [root]
    out = []
    try:
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if os.path.isdir(os.path.join(p, ".git")):
                out.append(p)
    except OSError:
        pass
    return out


def scan_repo(repo, history=True):
    finder = Finder(repo)
    scan_tree(repo, finder)
    if history:
        scan_history(repo, finder)
    return finder.findings


def permission_findings(repo, max_depth=4):
    """秘密情報ファイル（.env・秘密鍵等）が、所有者以外から読める権限になっていないか（POSIXのみ）。
    gitの管理外（.gitignore済みの.env等）も対象にするため、ファイルシステムを直接たどる。"""
    out = []
    base_depth = repo.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if dirpath.count("/") - base_depth >= max_depth:
            dirnames[:] = []
        for fn in filenames:
            if not SECRET_FILE_RE.search(fn) or EXAMPLE_RE.search(fn):
                continue
            full = os.path.join(dirpath, fn)
            try:
                mode = os.stat(full).st_mode & 0o777
            except OSError:
                continue
            if mode & 0o044:  # グループ・その他に読み取り権限がある
                rel = os.path.relpath(full, repo)
                out.append({"repo": os.path.basename(repo), "scope": "権限", "path": rel, "rule": "world-readable-secret-file",
                            "commit": "", "line": 0, "preview": f"mode={oct(mode)[2:]}",
                            "key": f"{os.path.basename(repo)}|権限|{rel}|world-readable-secret-file|{oct(mode)}"})
    return out
