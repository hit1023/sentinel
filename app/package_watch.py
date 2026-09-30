"""インストール済みパッケージの一覧（インベントリ）を集め、中央WebUIへ送る。

脆弱性DB(OSV.dev + CISA KEV)との突き合わせはマネージャー(webui/vuln.py)側で行う。
エージェントはパッケージ名とバージョンを送るだけで、外部の脆弱性DBには一切触れない
（全ホストが個別に外部APIを叩くより、マネージャーで1回まとめて照会する方が軽く、
DBの更新を拾った再照合もマネージャーだけで完結するため）。

現状の対象はdpkg系(Ubuntu/Debian)のみ。/var/lib/dpkg/statusを直接読むので、
Docker運用でもHITIDS_FS_PREFIX(/hostfs)経由でホスト側のパッケージDBを参照できる
（コンテナ内でdpkg-queryを実行するとコンテナ自身のパッケージが返ってしまう）。
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request

import central_config as central_config_mod
import paths

DPKG_STATUS = "/var/lib/dpkg/status"
OS_RELEASE = "/etc/os-release"


def parse_os_release(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip().strip('"')
    return result


def osv_ecosystem(os_release: dict) -> str | None:
    """OSVのecosystem名に変換する（例: Ubuntu 24.04 LTS → "Ubuntu:24.04:LTS"）。
    OSVのUbuntuデータはLTS版に":LTS"サフィックスが付くため、これを誤ると0件になる。"""
    distro = os_release.get("ID", "").lower()
    version_id = os_release.get("VERSION_ID", "")
    if not version_id:
        return None
    if distro == "ubuntu":
        suffix = ":LTS" if "LTS" in os_release.get("VERSION", "") else ""
        return f"Ubuntu:{version_id}{suffix}"
    if distro == "debian":
        return f"Debian:{version_id.split('.')[0]}"
    return None


def parse_dpkg_status(text: str) -> list[dict]:
    """dpkgのstatusファイルから、実際にインストール済みのパッケージをソースパッケージ単位で返す。
    OSVのUbuntu/Debianアドバイザリはバイナリ名(libssl3等)ではなくソースパッケージ名
    (openssl)で書かれているため、Source:フィールドで集約してから送る。"""
    sources: dict[tuple[str, str], set[str]] = {}
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                continue  # Description等の継続行は不要
            key, sep, value = line.partition(":")
            if not sep:
                continue
            fields[key.strip()] = value.strip()
        if not fields.get("Package") or not fields.get("Version"):
            continue
        # "deinstall ok config-files"(設定ファイルだけ残った削除済み)等は対象外
        if not fields.get("Status", "").endswith(" installed"):
            continue
        binary = fields["Package"]
        version = fields["Version"]
        source = fields.get("Source") or binary
        # Source: openssl (3.0.13-0ubuntu3) のように、バイナリと版が異なる場合は括弧で付く
        if "(" in source:
            name, _, rest = source.partition("(")
            source, version = name.strip(), rest.rstrip(")").strip()
        sources.setdefault((source, version), set()).add(binary)
    return [
        {"name": name, "version": version, "binaries": sorted(binaries)}
        for (name, version), binaries in sorted(sources.items())
    ]


class PackageWatcher:
    def __init__(self, config: dict, notifier, central_config: dict):
        self.config = config
        self.notifier = notifier
        self.central_config = central_config
        # パッケージ構成が変わらなくても、マネージャー側の表示が古くならないよう定期的に再送する
        self.resend_seconds = float(config.get("resend_hours", 24)) * 3600
        self.status_path = paths.resolve_fs_path(DPKG_STATUS)
        self.os_release_path = paths.resolve_fs_path(OS_RELEASE)
        self._last_mtime = None
        self._last_hash = None
        self._last_sent = 0.0
        self._unsupported_notified = False

    def _read(self, path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def check(self):
        try:
            mtime = os.stat(self.status_path).st_mtime
        except OSError:
            # dpkgの無いホスト(macOS等)。現状は対象外なので初回だけinfoで知らせて黙る
            if not self._unsupported_notified:
                self._unsupported_notified = True
                self.notifier.alert(
                    "package_watch",
                    "dpkgが見つからないため脆弱性照合用のパッケージ収集は対象外です（現状Ubuntu/Debianのみ対応）",
                    "info",
                )
            return

        now = time.time()
        if mtime == self._last_mtime and now - self._last_sent < self.resend_seconds:
            return

        os_release = parse_os_release(self._read(self.os_release_path))
        packages = parse_dpkg_status(self._read(self.status_path))
        digest = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest()
        if digest == self._last_hash and now - self._last_sent < self.resend_seconds:
            self._last_mtime = mtime
            return  # apt updateだけ等でstatusのmtimeが変わったが中身は同じ

        payload = {
            "os": {
                "id": os_release.get("ID", ""),
                "version_id": os_release.get("VERSION_ID", ""),
                "pretty_name": os_release.get("PRETTY_NAME", ""),
            },
            "ecosystem": osv_ecosystem(os_release),
            "packages": packages,
            "inventory_hash": digest,
            "collected_at": now,
        }
        # 送信に失敗した場合はmtime/hashを更新せず、次のループで再送させる
        if self._send(payload):
            self._last_mtime = mtime
            self._last_hash = digest
            self._last_sent = now

    def _send(self, payload: dict) -> bool:
        resolved = central_config_mod.resolve(self.central_config)
        if not resolved["enabled"] or not resolved["webui_url"]:
            return False
        payload["host"] = resolved["host_label"]
        headers = {"Content-Type": "application/json"}
        if resolved["ingest_token"]:
            headers["Authorization"] = f"Bearer {resolved['ingest_token']}"
        req = urllib.request.Request(
            f"{resolved['webui_url']}/api/ingest/packages",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            # パッケージ数が多いと受信側の保存に少し時間がかかるため通常より長めに待つ
            with urllib.request.urlopen(req, timeout=max(resolved["timeout_seconds"], 30)) as resp:
                resp.read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"中央WebUIへのパッケージ一覧送信に失敗: {e}", flush=True)
            return False
