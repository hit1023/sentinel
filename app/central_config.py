"""マルチホスト構成向け: 中央WebUIへの接続設定を解決する共通ヘルパー。

config.yamlの`central`セクションはgit管理下で全ホスト共通のため、
ホスト固有の値（WebUIのURL・ホスト名ラベル・共有トークン）は
config.yamlの値より環境変数(.env、gitignore対象)を優先させることで、
`git reset --hard`でのデプロイでもホストごとの設定が失われないようにする。
"""
import os
import socket


def resolve(config: dict) -> dict:
    config = config or {}
    return {
        "enabled": config.get("enabled", False),
        "webui_url": (
            os.environ.get("CENTRAL_WEBUI_URL") or config.get("webui_url") or ""
        ).rstrip("/"),
        "ingest_token": (
            os.environ.get("CENTRAL_INGEST_TOKEN") or config.get("ingest_token") or ""
        ),
        "host_label": (
            os.environ.get("CENTRAL_HOST_LABEL")
            or config.get("host_label")
            or socket.gethostname()
        ),
        "timeout_seconds": config.get("timeout_seconds", 5),
    }
