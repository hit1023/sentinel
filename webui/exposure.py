"""公開面の監視。インターネットから見えている自分の公開IPのポートを、外部の観測データ
（Shodan InternetDB: 認証不要・受動的）で定期的に確認し、**新しく開いたポート**や、
リスクの高いポート（DB・管理画面・リモートデスクトップ等）の公開、公開サービスの既知の脆弱性を通知する。

SENTINELのエージェントはホストの内側しか見られないため、ルーターのポート開放ミスや、
意図せず外へ出てしまったサービスは、この外からの観測でしか気づけない。
初回の観測は基準として記録する（すでにリスクの高いポートが見えていればその場でCRITICAL）。
"""
import json
import time
import urllib.error
import urllib.request

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
IPIFY_URL = "https://api.ipify.org"
# インターネットに公開されるべきでないポート（DB・リモート操作・管理画面）
DEFAULT_RISKY_PORTS = "21,23,135,139,445,1433,2375,2376,3306,3389,5432,5900,5984,6379,9200,11211,27017,81,5380,8877,9000,9443"
UA = {"User-Agent": "sentinel-ids/1.0"}


def _parse_ports(text: str) -> set[int]:
    out = set()
    for p in (text or "").replace("、", ",").split(","):
        p = p.strip()
        if p.isdigit():
            out.add(int(p))
    return out


def _http_json(url: str, timeout: int = 10):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class ExposureWatcher:
    def __init__(self, get_setting, set_setting, emit):
        self._get = get_setting
        self._set = set_setting
        self._emit = emit  # emit(category, message, severity, host)

    # --- 設定 ---
    def settings(self) -> dict:
        return {
            "enabled": self._get("exposure_enabled") == "true",
            "ips": [i.strip() for i in (self._get("exposure_ips") or "").replace("、", ",").split(",") if i.strip()],
            "risky_ports": self._get("exposure_risky_ports") or DEFAULT_RISKY_PORTS,
            "interval_hours": float(self._get("exposure_interval_hours") or 12),
        }

    def state(self) -> dict:
        try:
            return json.loads(self._get("exposure_state") or "{}")
        except ValueError:
            return {}

    # --- 観測 ---
    @staticmethod
    def observe(ip: str):
        """InternetDBの観測結果。観測データが無い(404)ときは「公開なし」として空を返し、通信失敗はNone。"""
        try:
            d = _http_json(INTERNETDB_URL.format(ip=ip))
        except urllib.error.HTTPError as e:
            return {"ports": [], "vulns": [], "hostnames": []} if e.code == 404 else None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        return {"ports": sorted(d.get("ports") or []), "vulns": sorted(d.get("vulns") or []), "hostnames": d.get("hostnames") or []}

    def _public_ips(self, configured: list[str]) -> list[str]:
        if configured:
            return configured
        try:  # 未設定なら、このマネージャーの外向きIP（=自宅の公開IP）を自動検出する
            req = urllib.request.Request(IPIFY_URL, headers=UA)
            with urllib.request.urlopen(req, timeout=8) as resp:
                ip = resp.read().decode().strip()
            return [ip] if ip.count(".") == 3 else []
        except (urllib.error.URLError, TimeoutError, OSError):
            return []

    # --- 実行 ---
    def run(self, force: bool = False, now: float | None = None) -> list[tuple[str, str]]:
        """観測して差分を通知する。送ったアラートの(severity, message)を返す。"""
        cfg = self.settings()
        now = now or time.time()
        if not cfg["enabled"] and not force:
            return []
        last = float(self._get("exposure_last_run") or 0)
        if not force and now - last < cfg["interval_hours"] * 3600:
            return []
        risky = _parse_ports(cfg["risky_ports"])
        state = self.state()
        sent = []

        def emit(sev, msg):
            self._emit("exposure_watch", msg, sev, "external")
            sent.append((sev, msg))

        for ip in self._public_ips(cfg["ips"]):
            cur = self.observe(ip)
            if cur is None:
                continue
            prev = state.get(ip)
            ports, vulns = set(cur["ports"]), set(cur["vulns"])
            if prev is None:
                hot = sorted(ports & risky)
                if hot:
                    emit("critical", f"リスクの高いポートがインターネットに公開されています: ip={ip} ports={','.join(map(str, hot))}")
                else:
                    emit("info", f"公開面の基準を記録しました: ip={ip} ports={','.join(map(str, sorted(ports))) or 'なし'}")
                if vulns:
                    emit("critical", f"公開サービスに既知の脆弱性が指摘されています: ip={ip} {', '.join(sorted(vulns)[:5])}")
            else:
                new_ports = ports - set(prev.get("ports", []))
                if new_ports:
                    hot = sorted(new_ports & risky)
                    sev = "critical" if hot else "warning"
                    emit(sev, f"公開ポートが増えました: ip={ip} 新規={','.join(map(str, sorted(new_ports)))}"
                              + (f"（リスクの高いポート: {','.join(map(str, hot))}）" if hot else ""))
                closed = set(prev.get("ports", [])) - ports
                if closed:
                    emit("info", f"公開ポートが閉じました: ip={ip} ports={','.join(map(str, sorted(closed)))}")
                new_vulns = vulns - set(prev.get("vulns", []))
                if new_vulns:
                    emit("critical", f"公開サービスに新たな既知の脆弱性が指摘されました: ip={ip} {', '.join(sorted(new_vulns)[:5])}")
            state[ip] = {"ports": sorted(ports), "vulns": sorted(vulns), "hostnames": cur["hostnames"], "seen": now}
        self._set("exposure_state", json.dumps(state))
        self._set("exposure_last_run", str(now))
        return sent
