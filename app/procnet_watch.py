"""プロセス・ネットワークの異常検知（未知プロセス、未知リスニングポート、高CPU）"""
import json
import os

try:
    import psutil
except ImportError:
    psutil = None

STATE_PATH = "/data/procnet_state.json"


class ProcNetWatcher:
    def __init__(self, config: dict, notifier):
        self.config = config
        self.notifier = notifier
        self.known_ports = set(config.get("known_listen_ports", []))
        self.known_keywords = [k.lower() for k in config.get("known_process_keywords", [])]
        self.cpu_alert_percent = config.get("cpu_alert_percent", 90)
        # 理論上の上限（全コードフル稼働）を超える値は計測異常とみなして無視する
        try:
            self._cpu_sane_max = max(100.0, psutil.cpu_count() * 100.0) if psutil else 100.0
        except Exception:
            self._cpu_sane_max = 3200.0
        self._state = self._load_state()
        if psutil is None:
            self.notifier.alert(
                "procnet_watch",
                "psutilが利用できないため、プロセス/ネットワーク監視を無効化します",
                "error",
            )

    def _load_state(self):
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        return {"known_ports_seen": [], "alerted_pids": []}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(self._state, f)

    def _is_known_process(self, name: str) -> bool:
        name = (name or "").lower()
        return any(kw in name for kw in self.known_keywords)

    def _check_listening_ports(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except (PermissionError, psutil.AccessDenied) as e:
            self.notifier.alert("procnet_watch", f"ネットワーク接続一覧の取得に失敗: {e}", "error")
            return
        alerted = set(self._state.get("known_ports_seen", []))
        for c in conns:
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            port = c.laddr.port
            if port in self.known_ports or port in alerted:
                continue
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self.notifier.alert(
                "procnet_watch",
                f"未登録のリスニングポートを検知: port={port} pid={c.pid} process={proc_name}",
                "warning",
            )
            alerted.add(port)
        self._state["known_ports_seen"] = list(alerted)

    def _check_processes(self):
        alerted_pids = set(self._state.get("alerted_pids", []))
        current_pids = set()
        # 注意: process_iter()のattrsに"cpu_percent"を含めると、ここでの内部呼び出しと
        # 下のp.cpu_percent(interval=None)がほぼ無時間差で二重計測になり、OSのクロック
        # 粒度による丸め誤差で数千%という荒唐無稽な値が出るバグがあった。
        # cpu_percentは属性取得に含めず、ループ内で一度だけ計測する。
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            info = p.info
            pid = info["pid"]
            current_pids.add(pid)
            name = info.get("name") or ""

            if pid not in alerted_pids and not self._is_known_process(name):
                cmdline = " ".join(info.get("cmdline") or [])[:200]
                self.notifier.alert(
                    "procnet_watch",
                    f"未知のプロセスを検知: pid={pid} name={name} cmd={cmdline}",
                    "warning",
                )
                alerted_pids.add(pid)

            try:
                cpu = p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu = 0
            if cpu > self._cpu_sane_max:
                # 計測直後の初回呼び出し等で発生する荒唐無稽な値（数千%等）は無視する
                continue
            if cpu >= self.cpu_alert_percent:
                self.notifier.alert(
                    "procnet_watch",
                    f"高CPU使用率のプロセス: pid={pid} name={name} cpu={cpu:.1f}%",
                    "warning",
                )

        # 終了したプロセスのpidは記憶から外す（無限に肥大化させない）
        self._state["alerted_pids"] = list(alerted_pids & current_pids)

    def check(self):
        if psutil is None:
            return
        self._check_processes()
        self._check_listening_ports()
        self._save_state()
