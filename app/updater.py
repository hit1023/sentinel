"""GitHub Releasesの最新版を定期チェックし、新バージョンがあれば通知する。
auto_apply有効時は新バイナリをダウンロード・SHA256検証してから自身を置き換え、
プロセスを終了する（systemd/launchdの自動再起動に任せる。プロセス内での
自己exec置換のような複雑なことはしない）。"""
import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import urllib.request

from version import get_version

GITHUB_API_LATEST = "https://api.github.com/repos/{repo}/releases/latest"
# install-native.sh/install-macos.shが実際に配置する先（両OSとも同じパス）
INSTALLED_BINARY_PATH = "/opt/sentinel/sentinel-agent"


def _asset_name() -> str | None:
    system = platform.system()
    machine = platform.machine()
    if system == "Linux":
        return "sentinel-agent-linux-x86_64.tar.gz"
    if system == "Darwin" and machine == "arm64":
        return "sentinel-agent-macos-arm64.tar.gz"
    return None


class UpdateChecker:
    def __init__(self, config: dict, notifier):
        self.enabled = config.get("enabled", False)
        self.check_interval_seconds = config.get("check_interval_seconds", 6 * 3600)
        self.auto_apply = config.get("auto_apply", False)
        self.github_repo = config.get("github_repo") or "hit1023/sentinel"
        self.notifier = notifier
        # 起動直後にも1回チェックしたいので0で初期化(起動直後に即チェックされる)
        self._last_check = 0.0

    def maybe_check(self):
        """main.pyのループから毎周期呼ばれる。check_interval_secondsに満たない間は何もしない。"""
        if not self.enabled:
            return
        now = time.time()
        if now - self._last_check < self.check_interval_seconds:
            return
        self._last_check = now
        try:
            self._check_once()
        except Exception as e:  # 更新チェックの失敗で監視ループ自体を止めない
            print(f"[updater] チェックに失敗: {e}", flush=True)

    def _check_once(self):
        latest = self._fetch_latest()
        if latest is None:
            return
        latest_tag, assets = latest
        latest_version = latest_tag.lstrip("v")
        current_version = get_version()
        if latest_version == current_version:
            return

        self.notifier.alert(
            "updater",
            f"新しいバージョン {latest_tag} が利用可能です（現在: v{current_version}）",
            "info",
        )

        if not self.auto_apply:
            return

        try:
            self._apply_update(latest_tag, assets)
        except Exception as e:
            self.notifier.alert("updater", f"自動アップデートに失敗: {e}", "warning")

    def _fetch_latest(self):
        url = GITHUB_API_LATEST.format(repo=self.github_repo)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "sentinel-agent", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = data.get("tag_name")
        if not tag:
            return None
        assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
        return tag, assets

    def _apply_update(self, tag: str, assets: dict):
        asset_name = _asset_name()
        if asset_name is None or asset_name not in assets:
            raise RuntimeError(f"このOS/アーキテクチャ向けのアセットが見つかりません（{asset_name}）")
        sha_name = asset_name + ".sha256"
        if sha_name not in assets:
            raise RuntimeError("チェックサムファイル(.sha256)が見つかりません")

        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, asset_name)
            _download(assets[asset_name], archive_path)

            sha_path = os.path.join(tmp, sha_name)
            _download(assets[sha_name], sha_path)
            with open(sha_path, "r", encoding="utf-8") as f:
                expected_sha = f.read().split()[0]

            actual_sha = _sha256_of(archive_path)
            if actual_sha != expected_sha:
                raise RuntimeError(f"チェックサム不一致（期待: {expected_sha}, 実際: {actual_sha}）")

            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=tmp, filter="data")
            new_binary = os.path.join(tmp, "sentinel-agent")
            if not os.path.isfile(new_binary):
                raise RuntimeError("展開したアーカイブにsentinel-agentが見つかりません")
            st = os.stat(new_binary)
            os.chmod(new_binary, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            # 展開したファイルシステムをまたぐと os.replace が失敗することがあるため、
            # 置き換え先と同じディレクトリに一旦コピーしてから原子的にrenameする。
            staged = INSTALLED_BINARY_PATH + ".new"
            shutil.copy2(new_binary, staged)
            os.replace(staged, INSTALLED_BINARY_PATH)

        self.notifier.alert("updater", f"{tag}への自動更新が完了、再起動します", "info")
        sys.exit(0)


def _download(url: str, dest: str):
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-agent"})
    with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
