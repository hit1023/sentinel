"""hit-linux-ids WebUI: 複数ホストのエージェントから /api/ingest 経由で
届くアラート・状態スナップショットを集約し、REST + WebSocketで配信する司令塔。"""
import asyncio
import json
import os
import sqlite3
import time
import uuid
from collections import Counter

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

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


_init_db()


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
async def ingest_alert(payload: dict, authorization: str | None = Header(default=None)):
    _check_token(authorization)
    record = dict(payload)
    record.setdefault("id", uuid.uuid4().hex)
    record.setdefault("host", "unknown")
    now = time.time()
    record.setdefault("epoch", now)
    if "timestamp" not in record:
        record["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record["epoch"]))
    # AIの判定より先に、ユーザー登録の抑制ルールを適用する
    # （「これは脅威ではない」と一度教えたものはAIの結果を待たず確実に黙らせる）
    _apply_suppressions(record)
    _append_alert(record)
    _persist_important(record)
    return {"ok": True, "id": record["id"]}


@app.get("/api/suppressions")
def api_list_suppressions():
    return {"suppressions": _load_suppressions()}


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
    last_24h = [a for a in alerts if now - a.get("epoch", 0) <= 86400]
    sev_counter = Counter(a.get("severity", "unknown") for a in last_24h)
    cat_counter = Counter(a.get("category", "unknown") for a in last_24h)

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
        "total_alerts_24h": len(last_24h),
        "by_severity": dict(sev_counter),
        "by_category": dict(cat_counter),
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
