"""WebUI向けの現在状態スナップショットを /data/status.json に書き出す"""
import json
import os
import time

try:
    import psutil
except ImportError:
    psutil = None

STATUS_PATH = "/data/status.json"


def write_status(extra: dict | None = None):
    snapshot = {
        "updated_at": time.time(),
        "process_count": None,
        "listen_port_count": None,
        "cpu_percent": None,
        "mem_percent": None,
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
    if extra:
        snapshot.update(extra)

    try:
        os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
        tmp_path = STATUS_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False)
        os.replace(tmp_path, STATUS_PATH)
    except OSError as e:
        print(f"status.json の書き込みに失敗: {e}", flush=True)
