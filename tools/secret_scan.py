#!/usr/bin/env python3
"""リポジトリ内の秘密情報（APIキー・トークン・秘密鍵・パスワード付きURL等）の混入を走査する。

外部ツール(gitleaks等)を入れずに使える自己完結のスキャナ。作業ツリーに加えて、
git履歴に一度でも含まれたものも見つける（履歴に残った鍵は、後で消しても漏れたままのため）。

  python3 tools/secret_scan.py /path/to/repo [/path/to/repo2 ...]
  python3 tools/secret_scan.py --root /Volumes/USBSSD/docker          # 直下の全gitリポジトリ
  python3 tools/secret_scan.py --root DIR --visibility visibility.tsv   # 公開リポジトリを強調
  python3 tools/secret_scan.py --json out.json ...

注意: 見つけた値そのものは出力しない（先頭4文字と長さだけ）。出力ファイル・ログ経由で
二次漏洩しないため。値の重複は同一とみなして1件にまとめる。
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

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
                              "commit": commit, "line": line, "preview": redact(value)})


def git(repo, *args, text=True):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=text, errors="replace")


def is_skipped(path: str) -> bool:
    parts = path.split("/")
    base = parts[-1]
    if any(p in SKIP_DIRS for p in parts[:-1]) or base in SKIP_FILES:
        return True
    return os.path.splitext(base)[1].lower() in SKIP_EXT or base.endswith(".min.js")


def scan_tree(repo, finder):
    out = git(repo, "ls-files", "-co", "--exclude-standard").stdout.splitlines()
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
    """.envのようなファイルがgit管理下（履歴含む）にあるか。値は見ず、存在だけを報告する。"""
    names = git(repo, "log", "--all", "--name-only", "--pretty=format:").stdout.splitlines()
    hits = sorted({n for n in names if re.search(r"(^|/)\.env(\.[\w.-]+)?$", n) and not n.endswith((".example", ".sample", ".template"))})
    return hits


def scan_history(repo, finder):
    proc = subprocess.Popen(["git", "-C", repo, "log", "--all", "-p", "-U0", "--no-color", "--diff-filter=AM", "--no-merges",
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


def find_repos(root):
    repos = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.isdir(os.path.join(p, ".git")):
            repos.append(p)
    return repos


def remote_name(repo):
    """origin URLからGitHub上のリポジトリ名を得る（ローカルのディレクトリ名と違うことがあるため）。"""
    url = git(repo, "remote", "get-url", "origin").stdout.strip()
    return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1].split(":")[-1]) if url else ""


def load_visibility(path):
    vis = {}
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            parts = line.strip().split("\t")
            if len(parts) == 2:
                vis[parts[1]] = parts[0]
    return vis


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="*")
    ap.add_argument("--root", help="直下のgitリポジトリをすべて走査する")
    ap.add_argument("--visibility", help="'PUBLIC<TAB>名前' 形式のファイル（公開リポジトリを強調）")
    ap.add_argument("--no-history", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()

    repos = list(args.repos)
    if args.root:
        repos += find_repos(args.root)
    if not repos:
        ap.error("リポジトリを指定してください")
    vis = load_visibility(args.visibility)

    all_findings, env_files = [], {}
    for repo in repos:
        name = os.path.basename(repo)
        remote = remote_name(repo)
        if remote and name not in vis and remote in vis:
            vis[name] = vis[remote]  # ディレクトリ名がGitHub上の名前と違う場合
        finder = Finder(repo)
        scan_tree(repo, finder)
        if not args.no_history:
            scan_history(repo, finder)
        env = tracked_env_files(repo)
        if env:
            env_files[os.path.basename(repo)] = env
        all_findings += finder.findings

    by_repo = {}
    for f in all_findings:
        by_repo.setdefault(f["repo"], []).append(f)
    print(f"走査したリポジトリ: {len(repos)}  検出: {len(all_findings)}件（{len(by_repo)}リポジトリ）\n")
    for repo in sorted(by_repo, key=lambda r: (vis.get(r) != "PUBLIC", r)):
        tag = f"[{vis[repo]}] " if repo in vis else ""
        print(f"■ {tag}{repo}  {len(by_repo[repo])}件")
        for f in by_repo[repo][:12]:
            where = f"{f['path']}:{f['line']}" if f["scope"] == "作業ツリー" else f"{f['path']} @{f['commit']}"
            print(f"   - {f['rule']:18} {f['scope']:5} {where}  {f['preview']}")
        if len(by_repo[repo]) > 12:
            print(f"   … ほか{len(by_repo[repo]) - 12}件")
    if env_files:
        print("\n.envがgit履歴に存在するリポジトリ（値は確認せず、存在のみ）:")
        for repo, names in sorted(env_files.items()):
            print(f"   {('[' + vis[repo] + '] ') if repo in vis else ''}{repo}: {', '.join(names[:5])}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"findings": all_findings, "env_files": env_files}, f, ensure_ascii=False, indent=1)
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
