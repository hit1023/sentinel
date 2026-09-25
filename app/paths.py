"""Dockerとネイティブ実行の両方で同じconfig.yaml/コードを使えるようにするための
パス解決ヘルパー。

Docker運用時はホストのファイルシステムが/hostfs、認証ログが/hostlogs配下に
マウントされるため、config.yaml側のwatch_paths/log_pathsは実パス表記
(例: /etc, /var/log/auth.log)のまま書いておき、Docker側だけ環境変数で
プレフィックスを付与する。ネイティブ実行では環境変数を設定しないため、
プレフィックスなし=実パスそのものになる。
"""
import os


def resolve_fs_path(path: str) -> str:
    """integrity_watch用。HITIDS_FS_PREFIX(Docker運用では/hostfs)を前置する。"""
    prefix = os.environ.get("HITIDS_FS_PREFIX", "")
    return prefix + path if prefix else path


def resolve_log_path(path: str) -> str:
    """auth_watch用。HITIDS_LOG_PREFIX(Docker運用では/hostlogs)を前置する。"""
    prefix = os.environ.get("HITIDS_LOG_PREFIX", "")
    return prefix + path if prefix else path


def data_dir() -> str:
    """state/baseline/cache等の永続化先ディレクトリ。ネイティブ実行では
    既定で/var/lib/sentinelを使う(Docker運用では/dataを明示的に指定する)。"""
    d = os.environ.get("HITIDS_DATA_DIR", "/data")
    os.makedirs(d, exist_ok=True)
    return d
