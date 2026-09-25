"""外向き通信の異常検知。LAN外への確立済み接続のうち、既知ポート以外への
通信や、既知の攻撃ツール（C2フレームワーク等）がよく使うポートへの通信を検知する"""
import ipaddress
import json
import os

try:
    import psutil
except ImportError:
    psutil = None

STATE_PATH = "/data/outbound_state.json"


class OutboundWatcher:
    def __init__(self, config: dict, notifier):
        self.config = config
        self.notifier = notifier
        self.known_ports = set(config.get("known_outbound_ports", []))
        self.suspicious_ports = set(config.get("suspicious_ports", []))
        self._state = self._load_state()
        if psutil is None:
            self.notifier.alert(
                "outbound_watch",
                "psutilが利用できないため、外向き通信監視を無効化します",
                "error",
            )

    def _load_state(self):
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        return {"alerted": []}

    def _save_state(self):
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(self._state, f)

    @staticmethod
    def _is_lan(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            # IPとして解釈できないものは安全側に倒して監視対象から外す
            return True

    def check(self):
        if psutil is None:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except (PermissionError, psutil.AccessDenied) as e:
            self.notifier.alert("outbound_watch", f"ネットワーク接続一覧の取得に失敗: {e}", "error")
            return

        # 同じ宛先(ip, port)への通信は一度アラートしたら以後は黙る
        # （procnet_watchの未登録ポート検知と同じ、永続dedup方式）
        alerted = set(tuple(x) for x in self._state.get("alerted", []))
        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            ip, port = c.raddr.ip, c.raddr.port
            if self._is_lan(ip):
                continue
            key = (ip, port)
            if key in alerted:
                continue

            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if port in self.suspicious_ports:
                self.notifier.alert(
                    "outbound_watch",
                    f"不審な外向き通信を検知（既知の攻撃ツールが使うポート）: "
                    f"{ip}:{port} pid={c.pid} process={proc_name}",
                    "critical",
                )
                alerted.add(key)
            elif self.known_ports and port not in self.known_ports:
                self.notifier.alert(
                    "outbound_watch",
                    f"未登録ポートへの外向き通信を検知: {ip}:{port} pid={c.pid} process={proc_name}",
                    "warning",
                )
                alerted.add(key)

        self._state["alerted"] = list(alerted)
        self._save_state()
