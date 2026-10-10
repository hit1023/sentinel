#!/usr/bin/env python3
"""リポジトリ内の秘密情報（APIキー・トークン・秘密鍵・パスワード付きURL等）の混入を走査する。

外部ツール(gitleaks等)を入れずに使える自己完結のスキャナ。作業ツリーに加えて、
git履歴に一度でも含まれたものも見つける（履歴に残った鍵は、後で消しても漏れたままのため）。
同じロジックは、エージェントの secret_watch が定期実行して「新しく混入したもの」を通知する。

  python3 tools/secret_scan.py /path/to/repo [/path/to/repo2 ...]
  python3 tools/secret_scan.py --root /Volumes/USBSSD/docker          # 直下の全gitリポジトリ
  python3 tools/secret_scan.py --root DIR --visibility visibility.tsv   # 公開リポジトリを強調
  python3 tools/secret_scan.py --json out.json ...

注意: 見つけた値そのものは出力しない（先頭4文字と長さだけ）。出力ファイル・ログ経由で
二次漏洩しないため。値の重複は同一とみなして1件にまとめる。
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import secretscan as core  # noqa: E402


def load_visibility(path):
    vis = {}
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            parts = line.strip().split("\t")
            if len(parts) == 2:
                vis[parts[1]] = parts[0]
    return vis


def remote_name(repo):
    """origin URLからGitHub上のリポジトリ名を得る（ローカルのディレクトリ名と違うことがあるため）。"""
    url = core.git(repo, "remote", "get-url", "origin").stdout.strip()
    return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1].split(":")[-1]) if url else ""


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
        repos += core.find_repos(args.root)
    if not repos:
        ap.error("リポジトリを指定してください")
    vis = load_visibility(args.visibility)

    all_findings, env_files = [], {}
    for repo in repos:
        name = os.path.basename(repo)
        remote = remote_name(repo)
        if remote and name not in vis and remote in vis:
            vis[name] = vis[remote]  # ディレクトリ名がGitHub上の名前と違う場合
        all_findings += core.scan_repo(repo, history=not args.no_history)
        all_findings += core.permission_findings(repo)
        env = core.tracked_env_files(repo)
        if env:
            env_files[name] = env

    by_repo = {}
    for f in all_findings:
        by_repo.setdefault(f["repo"], []).append(f)
    print(f"走査したリポジトリ: {len(repos)}  検出: {len(all_findings)}件（{len(by_repo)}リポジトリ）\n")
    for repo in sorted(by_repo, key=lambda r: (vis.get(r) != "PUBLIC", r)):
        tag = f"[{vis[repo]}] " if repo in vis else ""
        print(f"■ {tag}{repo}  {len(by_repo[repo])}件")
        for f in by_repo[repo][:12]:
            where = f"{f['path']}:{f['line']}" if f["scope"] == "作業ツリー" else f"{f['path']} @{f['commit']}" if f["scope"] == "履歴" else f["path"]
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
