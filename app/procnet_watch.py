"""プロセス・ネットワークの異常検知（未知プロセス、未知リスニングポート、高CPU）"""
import fnmatch
import ipaddress
import json
import os
import re
import time

try:
    import psutil
except ImportError:
    psutil = None

import paths

STATE_PATH = os.path.join(paths.data_dir(), "procnet_state.json")

# どのホストでも常に『既知』とみなすプロセス名（fnmatch・小文字）。SSHログインのたびに起動する
# ユーザーセッション用の常駐プロセスや、macOSのSpotlight等。config.yamlに書くと
# インストーラーが上書きしない既存ホストへ届かないため、コード側に持つ。
# ここに一致しても、実行ファイルが一時領域にある等の危険な兆候があれば通知する。
BUILTIN_KNOWN_PROCESS_PATTERNS = (
    "(sd-pam)", "sd-pam", "pipewire*", "wireplumber", "dbus-daemon", "dbus-broker*",
    "xdg-*", "fusermount*", "user-session-helper", "gvfs*", "at-spi*", "dconf-service",
    "mdworker*", "mds", "mds_stores", "corespotlightd",
)
# 実行ファイルがここにあるプロセスは、正規のソフトでは普通ありえない（マルウェアの定番の置き場所）
RISKY_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/")
# 名前だけで怪しいツール（完全一致・小文字）
ATTACK_TOOL_NAMES = frozenset({
    "nc", "ncat", "netcat", "socat", "xmrig", "minerd", "cpuminer", "kinsing", "kdevtmpfsi",
    "masscan", "hydra", "mimikatz", "chisel", "frpc",
})
SEEN_RETENTION_SECONDS = 30 * 86400
SEEN_MAX_ENTRIES = 20000

_DIGITS_RE = re.compile(r"\d+")


def _identity(name, exe, cmdline):
    """プロセスの『正体』。pidや端末番号・バージョン番号のように起動のたびに変わる数字は
    Nに潰して、同じ種類のプロセスを同一視する。"""
    return _DIGITS_RE.sub("N", f"{name}\0{exe}\0{cmdline}")[:300]


def _matches_builtin_known(name):
    name = (name or "").lower()
    return any(fnmatch.fnmatch(name, pat) for pat in BUILTIN_KNOWN_PROCESS_PATTERNS)


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
        self._ext_pids = None
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
        return {"known_ports_seen": []}

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

    def _external_conn_pids(self):
        """外部(プライベートでない)アドレスへ確立済みの通信を持つpidの集合。1回の巡回につき
        1度だけ取得する（新しい種類のプロセスが見つかったときだけ必要になるので遅延評価）。"""
        if self._ext_pids is None:
            pids = set()
            try:
                for c in psutil.net_connections(kind="inet"):
                    if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.pid:
                        continue
                    try:
                        addr = ipaddress.ip_address(c.raddr.ip)
                    except ValueError:
                        continue
                    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                        pids.add(c.pid)
            except (PermissionError, psutil.AccessDenied):
                pass
            self._ext_pids = pids
        return self._ext_pids

    def _risk_reasons(self, pid, name, exe, check_network=True):
        """新しい種類のプロセスに、単なる『未知』を超える危険な兆候があるか。
        兆候がなければ空リスト（＝INFO止まり）。ここが空でないものだけをWARNINGにする。"""
        reasons = []
        exe = exe or ""
        if exe.startswith(RISKY_EXE_PREFIXES):
            reasons.append(f"実行ファイルが一時領域にある({exe})")
        if exe.endswith(" (deleted)") or exe.startswith("memfd:"):
            reasons.append("実行ファイルが削除済み/メモリ上のみ")
        if (name or "").lower() in ATTACK_TOOL_NAMES:
            reasons.append("攻撃・不正利用で使われる名前のツール")
        if check_network and pid in self._external_conn_pids():
            reasons.append("外部のアドレスへ通信中")
        return reasons

    def _check_processes(self):
        """プロセスは『pid』ではなく『正体（名前＋実行ファイル＋コマンドの正規化）』で追う。
        SSHログインのたびに新しいpidで立ち上がる (sd-pam)/pipewire 等のセッション用プロセスを
        毎回『未知』と騒がないため。新しい正体を初めて見たときだけ通知する。
        通知の重さは兆候で決める: 危険な兆候あり→WARNING、ただ未知なだけ→INFO。"""
        self._ext_pids = None
        seen = self._state.get("seen_identities")
        first_run = seen is None
        if first_run:
            # 初回(または旧バージョンからの更新直後)は、いま動いているものを黙って基準にする。
            # ただし危険な兆候のあるものは、基準に入れつつ通知は出す。
            seen = {}
        now = time.time()
        registered = 0
        # 注意: process_iter()のattrsに"cpu_percent"を含めると、ここでの内部呼び出しと
        # 下のp.cpu_percent(interval=None)がほぼ無時間差で二重計測になり、OSのクロック
        # 粒度による丸め誤差で数千%という荒唐無稽な値が出るバグがあった。
        # cpu_percentは属性取得に含めず、ループ内で一度だけ計測する。
        for p in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            info = p.info
            pid = info["pid"]
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])[:200]

            ident = _identity(name, exe, cmdline)
            entry = seen.get(ident)
            if entry is None:
                registered += 1
                seen[ident] = {"first": now, "last": now}
                known = self._is_known_process(name) or _matches_builtin_known(name)
                # 外部通信は、既知のプロセス(sshd/nginx等)や初回の基準登録では普通のことなので兆候にしない
                reasons = self._risk_reasons(pid, name, exe, check_network=not known and not first_run)
                msg = f"未知のプロセスを検知: pid={pid} name={name} cmd={cmdline}"
                if reasons:
                    self.notifier.alert("procnet_watch", f"{msg} 【危険な兆候: {'、'.join(reasons)}】", "warning")
                elif not known and not first_run:
                    self.notifier.alert("procnet_watch", f"{msg} （新しい種類のプロセス）", "info")
            elif now - entry["last"] > 86400:
                entry["last"] = now  # 書き込みを減らすため、最終確認は1日に1回だけ更新する

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

        # 長く見ていない正体は記憶から外す（無限に肥大化させない）。旧バージョンのpid記録も捨てる。
        cutoff = now - SEEN_RETENTION_SECONDS
        if len(seen) > SEEN_MAX_ENTRIES:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1]["last"], reverse=True)[:SEEN_MAX_ENTRIES])
        seen = {k: v for k, v in seen.items() if v["last"] >= cutoff}
        self._state["seen_identities"] = seen
        self._state.pop("alerted_pids", None)
        if first_run:
            self.notifier.alert(
                "procnet_watch",
                f"プロセスの基準を登録しました（{registered}種類）。以降は新しい種類のプロセスだけを通知します",
                "info",
            )

    def check(self):
        if psutil is None:
            return
        self._check_processes()
        self._check_listening_ports()
        self._save_state()
