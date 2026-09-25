"""hit-linux-ids WebUI: 複数ホストのエージェントから /api/ingest 経由で
届くアラート・状態スナップショットを集約し、REST + WebSocketで配信する司令塔。"""
import asyncio
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.request
import uuid
from collections import Counter, defaultdict

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

# auth_watchのアラートメッセージから発信元IPを抜き出す（"from=IP" / "疑い: IP から"の2パターン）
AUTH_IP_RE = re.compile(r"from=([0-9a-fA-F:.]+)|疑い: ([0-9a-fA-F:.]+) から")
# procnet_watchのアラートメッセージから未知プロセス名を抜き出す（"name=X"パターン）
PROC_NAME_RE = re.compile(r"name=(\S+)")

DATA_DIR = os.environ.get("IDS_DATA_DIR", "/data")
ALERTS_JSONL = os.path.join(DATA_DIR, "alerts.jsonl")
HOSTS_STATUS_JSON = os.path.join(DATA_DIR, "hosts_status.json")
# CRITICAL/WARNINGだけを長期保管するSQLite（jsonlは直近tail表示用、こちらは監査・検索用）
ALERTS_DB = os.path.join(DATA_DIR, "alerts_important.db")
# jsonlに永続保存する重大度（これ以外=infoはjsonl(直近分)のみで十分なため対象外）
PERSIST_SEVERITIES = {"critical", "warning"}
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
# 何秒アップデートが無ければそのホストをオフライン扱いにするか
# （エージェントのinterval_secondsの3倍程度を想定した既定値）
HOST_STALE_SECONDS = int(os.environ.get("HOST_STALE_SECONDS", "300"))

app = FastAPI(title="hit-linux-ids WebUI")


def _db_connect():
    os.makedirs(os.path.dirname(ALERTS_DB), exist_ok=True)
    conn = sqlite3.connect(ALERTS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                epoch REAL NOT NULL,
                timestamp TEXT,
                host TEXT,
                category TEXT,
                severity TEXT,
                original_severity TEXT,
                message TEXT,
                ai_summary TEXT,
                ai_dismissed INTEGER DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_epoch ON alerts(epoch)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suppressions (
                id TEXT PRIMARY KEY,
                host TEXT,
                category TEXT NOT NULL,
                pattern TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_whitelist (
                id TEXT PRIMARY KEY,
                entry TEXT NOT NULL,
                label TEXT,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )


_init_db()

# --- CRITICALメール通知（mailman連携） ---
NOTIFY_SETTINGS_DEFAULTS = {
    "notify_email_enabled": "false",
    "notify_email_to": "",
    "notify_email_from": "",
    # h-1で稼働しているmailmanのエンドポイント（同一LAN内のため直接IPで指定）
    "mailman_url": "http://192.168.0.20:8765/send",
}


def _get_app_setting(key: str) -> str:
    with _db_connect() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    return NOTIFY_SETTINGS_DEFAULTS.get(key, "")


def _set_app_setting(key: str, value: str):
    with _db_connect() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _get_notify_settings() -> dict:
    return {
        "enabled": _get_app_setting("notify_email_enabled") == "true",
        "to": _get_app_setting("notify_email_to"),
        "from_addr": _get_app_setting("notify_email_from"),
        "mailman_url": _get_app_setting("mailman_url"),
    }


def _send_critical_email(record: dict, force: bool = False):
    """CRITICALアラート発生時にmailman(POST /send)経由でメール通知する。
    ingest_alertのレスポンスをブロックしないよう、呼び出し側でBackgroundTasksとして実行する想定。
    force=Trueの場合はenabledトグルを無視して送る（設定タブの「テスト送信」用）。"""
    settings = _get_notify_settings()
    if (not force and not settings["enabled"]) or not settings["to"]:
        return
    to_list = [a.strip() for a in settings["to"].split(",") if a.strip()]
    if not to_list:
        return

    host = record.get("host", "unknown")
    category = record.get("category", "")
    message = record.get("message", "")
    timestamp = record.get("timestamp", "")
    ai_summary = record.get("ai_summary")

    subject = f"[SENTINEL CRITICAL] {host} / {category}"
    text_lines = [
        f"host: {host}",
        f"category: {category}",
        f"time: {timestamp}",
        "",
        message,
    ]
    if ai_summary:
        text_lines += ["", f"AI: {ai_summary}"]
    text = "\n".join(text_lines)

    payload = {"to": to_list, "subject": subject, "text": text}
    if settings["from_addr"]:
        payload["from"] = settings["from_addr"]

    try:
        req = urllib.request.Request(
            settings["mailman_url"],
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        # メール送信の失敗でアラート処理自体を止めない。ローカルログにだけ残す。
        print(f"[notify] mailmanへのメール送信に失敗: {e}")


def _load_suppressions() -> list[dict]:
    with _db_connect() as conn:
        rows = conn.execute("SELECT * FROM suppressions ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def _matches_suppression(record: dict, rule: dict) -> bool:
    if rule.get("host") and rule["host"] != record.get("host"):
        return False
    if rule["category"] != record.get("category"):
        return False
    pattern = (rule.get("pattern") or "").strip().lower()
    if not pattern:
        return False
    return pattern in (record.get("message") or "").lower()


def _apply_suppressions(record: dict):
    """AIの判定結果とは無関係に、ユーザーが登録した『これは脅威ではない』ルールに
    一致するアラートを強制的にINFOへ格下げする。誤検知の再学習をAI任せにせず、
    確実に黙らせたいケース（例: 開発コマンド、既知の運用ファイル）向け。"""
    rules = _load_suppressions()
    for rule in rules:
        if _matches_suppression(record, rule):
            record.setdefault("original_severity", record.get("severity", "unknown"))
            record["severity"] = "info"
            record["suppressed"] = True
            record["suppression_pattern"] = rule["pattern"]
            return


def _load_ssh_whitelist() -> list[dict]:
    with _db_connect() as conn:
        rows = conn.execute("SELECT * FROM ssh_whitelist ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def _matches_ssh_whitelist(record: dict, entry: str) -> bool:
    """entryはIP単体・CIDR(例: 203.0.113.0/24)・国名のいずれか。
    IP/CIDRとして解釈できればメッセージ中のfrom=IPと照合し、できなければ
    location=国/都市(ドメイン) の部分文字列一致として扱う（国名でのホワイトリスト用）。"""
    message = record.get("message") or ""
    m = AUTH_IP_RE.search(message)
    ip = (m.group(1) or m.group(2)) if m else None
    try:
        network = ipaddress.ip_network(entry, strict=False)
        return ip is not None and ipaddress.ip_address(ip) in network
    except ValueError:
        return entry.strip().lower() in message.lower()


def _apply_ssh_whitelist(record: dict):
    """auth_watchのアラートのうち、登録済みのSSH許可リスト(IP/CIDR/国名)に一致する
    ものは、見慣れない国からのログイン等のCRITICAL判定も含めて確実にINFOへ格下げする。"""
    if record.get("category") != "auth_watch":
        return
    for entry in _load_ssh_whitelist():
        if _matches_ssh_whitelist(record, entry["entry"]):
            record.setdefault("original_severity", record.get("severity", "unknown"))
            record["severity"] = "info"
            record["suppressed"] = True
            record["suppression_pattern"] = f"SSH許可リスト: {entry['entry']}"
            return


def _persist_important(record: dict):
    # 元々critical/warningだったもの（AIに格下げされたものも含む）を対象にする。
    # そうしないとAIが非脅威判定してinfoに格下げしたアラートが監査ログから漏れる。
    severity = record.get("severity", "unknown")
    original_severity = record.get("original_severity", severity)
    if original_severity not in PERSIST_SEVERITIES:
        return
    with _db_connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO alerts
                (id, epoch, timestamp, host, category, severity, original_severity,
                 message, ai_summary, ai_dismissed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get("id"),
                record.get("epoch"),
                record.get("timestamp"),
                record.get("host"),
                record.get("category"),
                severity,
                original_severity,
                record.get("message"),
                record.get("ai_summary"),
                1 if record.get("ai_dismissed") else 0,
            ),
        )


def _check_token(authorization: str | None):
    if not INGEST_TOKEN:
        # トークン未設定の場合は開発用途として無認証で許可する
        return
    expected = f"Bearer {INGEST_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid ingest token")


def _read_alerts(limit: int = 200):
    if not os.path.exists(ALERTS_JSONL):
        return []
    # ファイル末尾からlimit件だけ読む（アラート数が増えても軽量に保つ）
    with open(ALERTS_JSONL, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _append_alert(record: dict):
    os.makedirs(os.path.dirname(ALERTS_JSONL), exist_ok=True)
    with open(ALERTS_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _read_hosts_status() -> dict:
    if not os.path.exists(HOSTS_STATUS_JSON):
        return {}
    try:
        with open(HOSTS_STATUS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _write_hosts_status(data: dict):
    os.makedirs(os.path.dirname(HOSTS_STATUS_JSON), exist_ok=True)
    tmp_path = HOSTS_STATUS_JSON + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp_path, HOSTS_STATUS_JSON)


@app.post("/api/ingest/alert")
async def ingest_alert(
    payload: dict,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
):
    _check_token(authorization)
    record = dict(payload)
    record.setdefault("id", uuid.uuid4().hex)
    record.setdefault("host", "unknown")
    now = time.time()
    record.setdefault("epoch", now)
    if "timestamp" not in record:
        record["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record["epoch"]))
    # AIの判定より先に、ユーザー登録の抑制ルール・SSH許可リストを適用する
    # （「これは脅威ではない」と一度教えたものはAIの結果を待たず確実に黙らせる）
    _apply_ssh_whitelist(record)
    _apply_suppressions(record)
    _append_alert(record)
    _persist_important(record)
    # 抑制・ホワイトリストを経てなお最終的にcriticalのままのものだけメール通知する
    # （レスポンスを待たせないようBackgroundTasksで非同期に送信）
    if record.get("severity") == "critical":
        background_tasks.add_task(_send_critical_email, record)
    return {"ok": True, "id": record["id"]}


@app.get("/api/suppressions")
def api_list_suppressions():
    return {"suppressions": _load_suppressions()}


def _reapply_suppressions_to_existing() -> int:
    """新規ルール登録前に既にjsonlへ書き込み済みのアラートに対しても、
    現在登録されている抑制ルールを遡って適用する。ルール登録前に届いた
    アラートは通常ingest時にしか評価されず放置されるため、明示的な
    再適用手段として用意した（『iwhで除外したい』という要望への対応）。"""
    if not os.path.exists(ALERTS_JSONL):
        return 0
    with open(ALERTS_JSONL, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated_ids = []
    out_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out_lines.append(line)
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        if not record.get("suppressed") and not record.get("ai_dismissed"):
            before = record.get("severity")
            _apply_ssh_whitelist(record)
            _apply_suppressions(record)
            if record.get("severity") != before:
                updated_ids.append(record.get("id"))
        out_lines.append(json.dumps(record, ensure_ascii=False) + "\n")

    tmp_path = ALERTS_JSONL + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.writelines(out_lines)
    os.replace(tmp_path, ALERTS_JSONL)

    if updated_ids:
        with _db_connect() as conn:
            conn.executemany(
                "UPDATE alerts SET severity = 'info' WHERE id = ?",
                [(i,) for i in updated_ids],
            )
    return len(updated_ids)


@app.post("/api/suppressions/reapply")
def api_reapply_suppressions():
    updated = _reapply_suppressions_to_existing()
    return {"ok": True, "updated": updated}


@app.post("/api/suppressions")
async def api_create_suppression(payload: dict):
    # ダッシュボード(ブラウザ)から直接叩くエンドポイントなので、
    # エージェント→WebUI間のingestトークンとは別扱い（WebUI自体が無認証設計のため一貫させる）
    category = (payload.get("category") or "").strip()
    pattern = (payload.get("pattern") or "").strip()
    host = (payload.get("host") or "").strip() or None
    if not category or not pattern:
        raise HTTPException(status_code=400, detail="category and pattern are required")
    rule_id = uuid.uuid4().hex
    with _db_connect() as conn:
        conn.execute(
            "INSERT INTO suppressions (id, host, category, pattern, created_at) VALUES (?, ?, ?, ?, ?)",
            (rule_id, host, category, pattern, time.time()),
        )
    return {"ok": True, "id": rule_id}


@app.delete("/api/suppressions/{rule_id}")
async def api_delete_suppression(rule_id: str):
    with _db_connect() as conn:
        conn.execute("DELETE FROM suppressions WHERE id = ?", (rule_id,))
    return {"ok": True}


@app.get("/api/ssh-whitelist")
def api_list_ssh_whitelist():
    return {"whitelist": _load_ssh_whitelist()}


@app.post("/api/ssh-whitelist")
async def api_create_ssh_whitelist(payload: dict):
    entry = (payload.get("entry") or "").strip()
    label = (payload.get("label") or "").strip()
    if not entry:
        raise HTTPException(status_code=400, detail="entry is required")
    entry_id = uuid.uuid4().hex
    with _db_connect() as conn:
        conn.execute(
            "INSERT INTO ssh_whitelist (id, entry, label, created_at) VALUES (?, ?, ?, ?)",
            (entry_id, entry, label, time.time()),
        )
    return {"ok": True, "id": entry_id}


@app.delete("/api/ssh-whitelist/{entry_id}")
async def api_delete_ssh_whitelist(entry_id: str):
    with _db_connect() as conn:
        conn.execute("DELETE FROM ssh_whitelist WHERE id = ?", (entry_id,))
    return {"ok": True}


@app.get("/api/notify-settings")
def api_get_notify_settings():
    return _get_notify_settings()


@app.post("/api/notify-settings")
async def api_set_notify_settings(payload: dict):
    if "enabled" in payload:
        _set_app_setting("notify_email_enabled", "true" if payload["enabled"] else "false")
    if "to" in payload:
        _set_app_setting("notify_email_to", (payload["to"] or "").strip())
    if "from_addr" in payload:
        _set_app_setting("notify_email_from", (payload["from_addr"] or "").strip())
    if "mailman_url" in payload:
        _set_app_setting("mailman_url", (payload["mailman_url"] or "").strip())
    return {"ok": True, "settings": _get_notify_settings()}


@app.post("/api/notify-settings/test")
async def api_test_notify_settings():
    """設定タブから「テスト送信」した際に叩くエンドポイント。実際のアラートを
    経由せず、mailman連携が正しく動くかその場で確認できるようにする。"""
    settings = _get_notify_settings()
    if not settings["to"]:
        raise HTTPException(status_code=400, detail="宛先メールアドレスが未設定です")
    _send_critical_email({
        "host": "sentinel-test",
        "category": "test",
        "message": "これはSENTINELからのテスト通知です。この文面が届いていればmailman連携は正常です。",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "severity": "critical",
    }, force=True)
    return {"ok": True}


@app.post("/api/ingest/status")
async def ingest_status(payload: dict, authorization: str | None = Header(default=None)):
    _check_token(authorization)
    host = payload.get("host") or "unknown"
    hosts = _read_hosts_status()
    hosts[host] = {**payload, "host": host, "received_at": time.time()}
    _write_hosts_status(hosts)
    return {"ok": True}


@app.get("/api/hosts")
def api_hosts():
    hosts = _read_hosts_status()
    now = time.time()
    out = []
    for host, info in hosts.items():
        last_seen = info.get("received_at") or info.get("updated_at") or 0
        out.append({**info, "online": (now - last_seen) <= HOST_STALE_SECONDS})
    out.sort(key=lambda h: h.get("host", ""))
    return {"hosts": out, "server_time": now}


@app.get("/api/alerts")
def api_alerts(limit: int = 200, host: str | None = None):
    alerts = _read_alerts(limit if not host else 5000)
    if host:
        alerts = [a for a in alerts if a.get("host") == host][-limit:]
    return {"alerts": list(reversed(alerts))}


@app.get("/api/alerts/history")
def api_alerts_history(
    limit: int = 500,
    host: str | None = None,
    severity: str | None = None,
    since_epoch: float | None = None,
):
    """CRITICAL/WARNING（元severity）だけをSQLiteから長期検索するエンドポイント。
    jsonlのtail(直近5000行)と違い、ホストのローテーション・再起動を跨いだ過去分も引ける。"""
    limit = min(max(limit, 1), 5000)
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if host:
        query += " AND host = ?"
        params.append(host)
    if severity:
        query += " AND (severity = ? OR original_severity = ?)"
        params.extend([severity, severity])
    if since_epoch:
        query += " AND epoch >= ?"
        params.append(since_epoch)
    query += " ORDER BY epoch DESC LIMIT ?"
    params.append(limit)
    with _db_connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return {"alerts": [dict(r) for r in rows]}


@app.get("/api/stats")
def api_stats():
    alerts = _read_alerts(5000)
    now = time.time()
    since_epoch = now - 86400
    last_24h = [a for a in alerts if now - a.get("epoch", 0) <= 86400]

    # critical/warningはjsonlの直近5000行だけでは取りこぼす(procnet_watch等の
    # 大量WARNING/INFOに押し出されて古いCRITICALが集計から漏れる)ため、
    # 全件を長期保管しているSQLite(alerts_important.db)から正確な件数を取る。
    # infoはSQLiteに保存していないためjsonl(直近分)のまま。
    with _db_connect() as conn:
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as c FROM alerts WHERE epoch >= ? AND severity IN ('critical','warning') GROUP BY severity",
            (since_epoch,),
        ).fetchall()
        heatmap_rows = conn.execute(
            "SELECT host, epoch, severity FROM alerts WHERE epoch >= ? AND severity IN ('critical','warning')",
            (since_epoch,),
        ).fetchall()

    sev_counter = Counter(a.get("severity", "unknown") for a in last_24h if a.get("severity") not in ("critical", "warning"))
    for row in sev_rows:
        sev_counter[row["severity"]] = row["c"]
    cat_counter = Counter(a.get("category", "unknown") for a in last_24h)

    # 直近24時間を1時間単位のバケットに分け、ホストごとの検知傾向をヒートマップ表示できるようにする
    # （全ホスト合算だと、特定の1台だけが荒れている状況が他ホストの数字に埋もれてしまうため）
    now_hour = int(now // 3600)
    hourly_by_host = defaultdict(lambda: defaultdict(Counter))
    hosts_seen = set()
    for a in last_24h:
        host = a.get("host", "unknown")
        hosts_seen.add(host)
        offset = now_hour - int(a.get("epoch", 0) // 3600)
        if 0 <= offset < 24:
            sev = a.get("severity", "info")
            if sev in ("critical", "warning"):
                continue  # critical/warningはSQLite由来の集計で後段に統一する
            hourly_by_host[host][offset]["info"] += 1
    for row in heatmap_rows:
        host = row["host"] or "unknown"
        hosts_seen.add(host)
        offset = now_hour - int(row["epoch"] // 3600)
        if 0 <= offset < 24:
            hourly_by_host[host][offset][row["severity"]] += 1

    def _build_heatmap_row(host_buckets):
        row = []
        for offset in range(23, -1, -1):
            c = host_buckets.get(offset, Counter())
            row.append({
                "hour_start": (now_hour - offset) * 3600,
                "critical": c.get("critical", 0),
                "warning": c.get("warning", 0),
                "info": c.get("info", 0),
            })
        return row

    heatmap_by_host = {
        host: _build_heatmap_row(hourly_by_host[host])
        for host in sorted(hosts_seen)
    }

    # 認証失敗の発信元IPランキング（ログイン成功は除外し、ブルートフォース/
    # 存在しないユーザー/要注意ユーザーへの失敗試行だけを集計する）
    ip_counter = Counter()
    for a in last_24h:
        if a.get("category") != "auth_watch":
            continue
        msg = a.get("message", "")
        if "ログイン成功" in msg:
            continue
        m = AUTH_IP_RE.search(msg)
        if m:
            ip_counter[m.group(1) or m.group(2)] += 1
    top_auth_ips = [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(10)]

    # procnet_watchで頻出している未知プロセス名のランキング（known_process_keywordsを
    # チューニングする際の判断材料。「未知のプロセスを検知: pid=... name=X cmd=...」から抽出）
    proc_counter = Counter()
    for a in last_24h:
        if a.get("category") != "procnet_watch":
            continue
        m = PROC_NAME_RE.search(a.get("message", ""))
        if m:
            proc_counter[m.group(1)] += 1
    top_processes = [{"name": name, "count": c} for name, c in proc_counter.most_common(10)]

    hosts_status = _read_hosts_status()
    hosts_out = []
    online_cpu = []
    online_mem = []
    total_processes = 0
    total_ports = 0
    for host, info in hosts_status.items():
        last_seen = info.get("received_at") or info.get("updated_at") or 0
        online = (now - last_seen) <= HOST_STALE_SECONDS
        hosts_out.append({**info, "online": online})
        if online:
            if info.get("cpu_percent") is not None:
                online_cpu.append(info["cpu_percent"])
            if info.get("mem_percent") is not None:
                online_mem.append(info["mem_percent"])
            total_processes += info.get("process_count") or 0
            total_ports += info.get("listen_port_count") or 0
    hosts_out.sort(key=lambda h: h.get("host", ""))

    aggregate = {
        "process_count": total_processes or None,
        "listen_port_count": total_ports or None,
        "cpu_percent": (sum(online_cpu) / len(online_cpu)) if online_cpu else None,
        "mem_percent": (sum(online_mem) / len(online_mem)) if online_mem else None,
        "updated_at": max(
            (h.get("received_at") or 0 for h in hosts_out), default=None
        ) or None,
        "online_host_count": sum(1 for h in hosts_out if h["online"]),
        "host_count": len(hosts_out),
    }

    return {
        "status": aggregate,
        "hosts": hosts_out,
        # len(last_24h)はjsonlの直近5000行という上限に張り付くことがあるため、
        # critical/warningがSQLiteベースに直った sev_counter の合計を正とする。
        "total_alerts_24h": sum(sev_counter.values()),
        "by_severity": dict(sev_counter),
        "by_category": dict(cat_counter),
        "heatmap_by_host": heatmap_by_host,
        "top_auth_ips": top_auth_ips,
        "top_processes": top_processes,
        "server_time": now,
    }


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    last_size = os.path.getsize(ALERTS_JSONL) if os.path.exists(ALERTS_JSONL) else 0
    try:
        while True:
            await asyncio.sleep(1.5)
            if not os.path.exists(ALERTS_JSONL):
                continue
            size = os.path.getsize(ALERTS_JSONL)
            if size < last_size:
                # ローテーション等で縮小した場合は先頭から
                last_size = 0
            if size > last_size:
                with open(ALERTS_JSONL, "r", encoding="utf-8") as f:
                    f.seek(last_size)
                    new_lines = f.readlines()
                    last_size = f.tell()
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    await ws.send_json(record)
    except WebSocketDisconnect:
        pass


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
