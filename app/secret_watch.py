"""秘密情報の混入検知。設定した場所のgitリポジトリを定期的に走査し、APIキー・トークン・秘密鍵などが
**新しく**混入したら通知する（作業ツリーとgit履歴の両方）。.envや秘密鍵が他ユーザーから
読める権限になっていないかも見る。

漏洩の入口として最も多いのは認証情報の混入・流出なので、リポジトリに入った瞬間に気づけるようにする。
見つけた値そのものは通知に含めない（先頭4文字と長さのみ）。初回の走査では、すでに存在するものを
リポジトリごとにまとめて報告し、以後は新規分だけを通知する。
"""
import json
import os
import time

import paths
import secretscan

STATE_PATH = os.path.join(paths.data_dir(), "secret_watch_state.json")
HOUR = 3600


class SecretWatcher:
    def __init__(self, config: dict, notifier):
        self.notifier = notifier
        # config.yamlはgit管理で全ホスト共通のため、ホストごとの走査場所は環境変数SECRET_WATCH_ROOTS
        # （カンマ区切り）でも指定できる（WEB_LOG_PATHSと同じ方式）
        env_roots = [p.strip() for p in os.environ.get("SECRET_WATCH_ROOTS", "").split(",") if p.strip()]
        self.roots = [paths.resolve_fs_path(p) for p in (env_roots or config.get("scan_roots", [])) if p]
        self.interval = float(config.get("interval_hours", 24)) * HOUR
        self.history_interval = float(config.get("history_interval_hours", 168)) * HOUR
        self.check_permissions = bool(config.get("check_permissions", True))
        self._state = self._load_state()
        self._missing_reported = False

    def _load_state(self):
        try:
            with open(STATE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"last_run": 0, "last_history": 0, "known": []}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        self._state["known"] = self._state["known"][-20000:]  # 無限に肥大化させない
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f)
        os.replace(tmp, STATE_PATH)

    def _notify_repo(self, repo, findings, first_run):
        high = [f for f in findings if f["rule"] in secretscan.HIGH_CONFIDENCE]
        perms = [f for f in findings if f["rule"] == "world-readable-secret-file"]
        by_rule = {}
        for f in findings:
            by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        breakdown = ", ".join(f"{r}×{n}" for r, n in sorted(by_rule.items(), key=lambda x: -x[1])[:5])
        samples = []
        for f in (high or findings)[:3]:
            where = f["path"] if f["scope"] != "履歴" else f"{f['path']}@{f['commit']}"
            samples.append(f"{where}[{f['rule']} {f['preview']}]")
        head = "秘密情報の混入を検知" if not first_run else "秘密情報の混入を検知（初回走査）"
        if findings and len(perms) == len(findings):
            head = "秘密情報ファイルが他のユーザーから読める権限です"
        msg = f"{head}: repo={repo} {len(findings)}件（{breakdown}） 例: {'; '.join(samples)}"
        severity = "critical" if high else "warning"
        # 値が出力に残らないとはいえ、AIの判断で静かにさせたくない（鍵の漏洩は取り返しがつかない）
        self.notifier.alert("secret_watch", msg[:600], severity, allow_ai_dismiss=False)

    def check(self, force: bool = False):
        now = time.time()
        if not force and now - self._state.get("last_run", 0) < self.interval:
            return
        repos = []
        for root in self.roots:
            repos += secretscan.find_repos(root)
        if self.roots and not repos:
            if not self._missing_reported:
                self.notifier.alert("secret_watch", "走査対象のgitリポジトリが見つかりません。scan_rootsを確認してください", "error")
                self._missing_reported = True
            self._state["last_run"] = now
            self._save_state()
            return
        self._missing_reported = False

        history = now - self._state.get("last_history", 0) >= self.history_interval
        first_run = not self._state.get("last_run")
        known = set(self._state.get("known", []))
        for repo in repos:
            try:
                findings = secretscan.scan_repo(repo, history=history)
                if self.check_permissions:
                    findings += secretscan.permission_findings(repo)
            except Exception as e:  # 1つのリポジトリの失敗で全体を止めない
                self.notifier.alert("secret_watch", f"走査に失敗: {os.path.basename(repo)}: {e}", "error")
                continue
            new = [f for f in findings if f["key"] not in known]
            if new:
                self._notify_repo(os.path.basename(repo), new, first_run)
                known.update(f["key"] for f in new)
        self._state["known"] = sorted(known)
        self._state["last_run"] = now
        if history:
            self._state["last_history"] = now
        self._save_state()
