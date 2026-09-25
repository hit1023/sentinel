"""ホストの現在状態スナップショットを組み立て、中央WebUIへHTTP POSTする"""
import json
import time
import urllib.error
import urllib.request

try:
    import psutil
except ImportError:
    psutil = None

import central_config as central_config_mod
from version import get_version


def build_snapshot() -> dict:
    snapshot = {
        "updated_at": time.time(),
        "process_count": None,
        "listen_port_count": None,
        "cpu_percent": None,
        "mem_percent": None,
        "agent_version": get_version(),
    }
    if psutil is not None:
        try:
            snapshot["process_count"] = len(psutil.pids())
        except (psutil.Error, OSError):
            pass
        try:
            conns = psutil.net_connections(kind="inet")
            snapshot["listen_port_count"] = len(
                {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr}
            )
        except (psutil.Error, OSError, PermissionError):
            pass
        try:
            snapshot["cpu_percent"] = psutil.cpu_percent(interval=None)
            snapshot["mem_percent"] = psutil.virtual_memory().percent
        except (psutil.Error, OSError):
            pass
    return snapshot


def report_status(central_config: dict):
    """組み立てたスナップショットを中央WebUIの/api/ingest/statusへ送信する。
    central.enabledがfalse、あるいは送信失敗時は静かに諦める
    （ステータス更新の失敗で監視ループ自体を止めない）。"""
    resolved = central_config_mod.resolve(central_config)
    if not resolved["enabled"] or not resolved["webui_url"]:
        return

    snapshot = build_snapshot()
    snapshot["host"] = resolved["host_label"]

    token = resolved["ingest_token"]
    timeout = resolved["timeout_seconds"]
    webui_url = resolved["webui_url"]

    url = f"{webui_url}/api/ingest/status"
    data = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"中央WebUIへのステータス送信に失敗: {e}", flush=True)
