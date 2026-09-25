"""簡易ファイル整合性監視（AIDE風）。指定パス配下のハッシュを取り、変更/追加/削除を検知する"""
import fnmatch
import glob
import hashlib
import json
import os

import paths


def _sha256(path, chunk_size=65536):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class IntegrityWatcher:
    def __init__(self, config: dict, notifier):
        self.config = config
        self.notifier = notifier
        # watch_pathsはconfig.yaml上は実パス表記（例: /etc, /home/*/.ssh）で書き、
        # Docker運用時だけHITIDS_FS_PREFIX(通常/hostfs)を前置してホスト実体を見に行く。
        self.watch_paths = [paths.resolve_fs_path(p) for p in config.get("watch_paths", [])]
        # exclude_patterns/critical_patternsは先頭が*から始まるfnmatchパターンのため
        # プレフィックスの有無に関わらずマッチするので変換不要。
        self.exclude_patterns = config.get("exclude_patterns", [])
        # config.get(key, default)は空文字("" = 未設定の意図)でもキーが存在すれば
        # そのまま返しdefaultにフォールバックしないため、明示的にorで判定する
        # （notify.pyのlog_fileで踏んだのと同じ罠）。
        self.baseline_path = config.get("baseline_path") or os.path.join(
            paths.data_dir(), "integrity_baseline.json"
        )
        # ここに一致するパスは、新規作成・削除であっても（通常はwarning止まりのところ）
        # 即座にcriticalとして扱う。SSH公開鍵はroot以外の全ユーザー分を対象にしたいので
        # watch_paths側はglobパターン（例: /home/*/.ssh）にも対応させている
        self.critical_patterns = config.get("critical_patterns", ["*/.ssh/*"])

    def _is_excluded(self, path):
        return any(fnmatch.fnmatch(path, pat) for pat in self.exclude_patterns)

    def _is_critical_path(self, path):
        return any(fnmatch.fnmatch(path, pat) for pat in self.critical_patterns)

    def _scan(self):
        result = {}
        expanded_bases = []
        for pattern in self.watch_paths:
            if any(ch in pattern for ch in "*?["):
                expanded_bases.extend(glob.glob(pattern))
            else:
                expanded_bases.append(pattern)
        for base in expanded_bases:
            if not os.path.exists(base):
                continue
            if os.path.isfile(base):
                candidates = [base]
            else:
                candidates = []
                for root, _dirs, files in os.walk(base):
                    for name in files:
                        candidates.append(os.path.join(root, name))
            for path in candidates:
                if self._is_excluded(path):
                    continue
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                digest = _sha256(path)
                if digest is None:
                    continue
                result[path] = {"hash": digest, "size": st.st_size, "mtime": st.st_mtime}
        return result

    def _load_baseline(self):
        if os.path.exists(self.baseline_path):
            try:
                with open(self.baseline_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def _save_baseline(self, data):
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def check(self):
        current = self._scan()
        baseline = self._load_baseline()

        if baseline is None:
            self._save_baseline(current)
            self.notifier.alert(
                "integrity_watch",
                f"ベースラインを新規作成しました（監視対象ファイル数: {len(current)}）",
                "info",
            )
            return

        base_paths = set(baseline.keys())
        cur_paths = set(current.keys())

        for path in sorted(cur_paths - base_paths):
            if self._is_critical_path(path):
                self.notifier.alert(
                    "integrity_watch",
                    f"SSH関連ファイルの新規作成を検知（不正な鍵の追加の可能性）: {path}",
                    "critical",
                )
            else:
                self.notifier.alert("integrity_watch", f"新規ファイルを検知: {path}", "warning")

        for path in sorted(base_paths - cur_paths):
            if self._is_critical_path(path):
                self.notifier.alert(
                    "integrity_watch",
                    f"SSH関連ファイルの削除を検知: {path}",
                    "critical",
                )
            else:
                self.notifier.alert("integrity_watch", f"ファイルの削除を検知: {path}", "warning")

        for path in sorted(cur_paths & base_paths):
            if current[path]["hash"] != baseline[path]["hash"]:
                if self._is_critical_path(path):
                    self.notifier.alert(
                        "integrity_watch",
                        f"SSH公開鍵ファイルの変更を検知（不正な鍵の追加/改ざんの可能性）: {path}",
                        "critical",
                    )
                else:
                    self.notifier.alert(
                        "integrity_watch",
                        f"ファイル改ざんの疑い（ハッシュ不一致）: {path}",
                        "critical",
                    )

        self._save_baseline(current)
