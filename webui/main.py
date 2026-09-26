"""hit-linux-ids WebUI: 複数ホストのエージェントから /api/ingest 経由で
届くアラート・状態スナップショットを集約し、REST + WebSocketで配信する司令塔。"""
import asyncio
import datetime
import ipaddress
import json
import os
import re
import smtplib
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter, defaultdict
from email.message import EmailMessage

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

# コンテナはTZ設定に関わらずUTCで動くことが多いため、表示・保存する時刻は
# システムのローカルタイムに依存せずJST固定で生成する。
JST = datetime.timezone(datetime.timedelta(hours=9))

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

# --- デイリーレポートのAI総括用（agentのai_triageとは別に、webui単体で
# Cloudflare AI Gatewayを呼ぶ。未設定でも動く：その場合はAI総括なしの
# 統計のみのレポートを送る） ---
CF_AI_ACCOUNT_ID = os.environ.get("CF_AI_GATEWAY_ACCOUNT_ID", "")
CF_AI_GATEWAY_ID = os.environ.get("CF_AI_GATEWAY_ID", "")
CF_AI_TOKEN = os.environ.get("CF_AI_GATEWAY_TOKEN", "")
CF_AI_MODEL = os.environ.get("CF_AI_GATEWAY_MODEL", "@cf/meta/llama-3.1-8b-instruct-fast")

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

# --- CRITICALメール通知 ---
# 2方式を用意し、設定されている方を使う（両方設定されていればSMTPを優先）:
#   - webhook_url: 自前の軽量メール送信API（{to, subject, text, from}をJSON POST）に
#     投げる従来方式。運用中のホストは既にこれで動いているため後方互換として残す。
#   - smtp_*: Gmail等、利用者自身のメールプロバイダのSMTPを直接使う汎用方式。
#     cloneした人が自分のメール送信手段を持ち込めるよう、これを新規セットアップの
#     既定の案内先とする（README参照）。
NOTIFY_SETTINGS_DEFAULTS = {
    "notify_email_enabled": "false",
    "notify_email_to": "",
    "notify_email_from": "",
    "webhook_url": "",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_use_tls": "true",
    # --- デイリーレポート ---
    "daily_report_enabled": "false",
    "daily_report_hour": "9",  # JST、0-23
}


def _get_app_setting(key: str) -> str:
    with _db_connect() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    if key == "webhook_url":
        # 旧キー名(mailman_url)で既に設定済みの既存ホストとの後方互換。
        with _db_connect() as conn:
            legacy = conn.execute(
                "SELECT value FROM app_settings WHERE key = 'mailman_url'"
            ).fetchone()
        if legacy is not None:
            return legacy["value"]
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
        "webhook_url": _get_app_setting("webhook_url"),
        "smtp_host": _get_app_setting("smtp_host"),
        "smtp_port": _get_app_setting("smtp_port"),
        "smtp_user": _get_app_setting("smtp_user"),
        "smtp_password": _get_app_setting("smtp_password"),
        "smtp_use_tls": _get_app_setting("smtp_use_tls") == "true",
    }


def _send_via_webhook(webhook_url: str, to_list: list, subject: str, text: str, from_addr: str):
    payload = {"to": to_list, "subject": subject, "text": text}
    if from_addr:
        payload["from"] = from_addr
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=8)


def _send_via_smtp(settings: dict, to_list: list, subject: str, text: str):
    from_addr = settings["from_addr"] or settings["smtp_user"] or "sentinel@localhost"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_list)
    msg.set_content(text)

    smtp_port = int(settings["smtp_port"] or 587)
    with smtplib.SMTP(settings["smtp_host"], smtp_port, timeout=10) as smtp:
        if settings["smtp_use_tls"]:
            smtp.starttls()
        if settings["smtp_user"]:
            smtp.login(settings["smtp_user"], settings["smtp_password"])
        smtp.send_message(msg)


# --- デイリーレポート ---

DAILY_REPORT_SYSTEM_PROMPT = (
    "あなたはLinuxサーバー群のセキュリティ監視を担当するSOCアナリストです。"
    "渡される1日分のアラート統計(JSON: 重大度別件数、カテゴリ別件数、ホスト別件数、"
    "CRITICALアラートの実例メッセージ)を読み、日本語で3〜5文程度の総括コメントを"
    "書いてください。件数の規模感、特に注意すべき点（急増しているカテゴリ、特定ホストへの"
    "集中、実例に不審な内容が含まれるか等）、総じて平常運転か注意が必要かの所感を含めてください。"
    "前置き・見出し・箇条書き記号は禁止、地の文で簡潔に。"
)


def _get_daily_report_settings() -> dict:
    return {
        "enabled": _get_app_setting("daily_report_enabled") == "true",
        "hour": int(_get_app_setting("daily_report_hour") or "9"),
    }


def _collect_period_stats(start_epoch: float, end_epoch: float) -> dict:
    """指定期間[start_epoch, end_epoch)のアラートを集計する。
    critical/warningはSQLite(全件正確)、infoはjsonl直近分ベース（/api/statsと同じ設計）。"""
    with _db_connect() as conn:
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as c FROM alerts WHERE epoch >= ? AND epoch < ? "
            "AND severity IN ('critical','warning') GROUP BY severity",
            (start_epoch, end_epoch),
        ).fetchall()
        host_rows = conn.execute(
            "SELECT host, COUNT(*) as c FROM alerts WHERE epoch >= ? AND epoch < ? "
            "AND severity IN ('critical','warning') GROUP BY host",
            (start_epoch, end_epoch),
        ).fetchall()
        sample_rows = conn.execute(
            "SELECT host, category, message, timestamp FROM alerts WHERE epoch >= ? AND epoch < ? "
            "AND severity = 'critical' ORDER BY epoch DESC LIMIT 10",
            (start_epoch, end_epoch),
        ).fetchall()

    period_alerts = [a for a in _read_alerts(5000) if start_epoch <= a.get("epoch", 0) < end_epoch]

    sev_counter = Counter(
        a.get("severity", "unknown") for a in period_alerts if a.get("severity") not in ("critical", "warning")
    )
    for row in sev_rows:
        sev_counter[row["severity"]] = row["c"]

    cat_counter = Counter(a.get("category", "unknown") for a in period_alerts)

    host_counter = Counter()
    for row in host_rows:
        host_counter[row["host"] or "unknown"] += row["c"]

    return {
        "by_severity": dict(sev_counter),
        "by_category": dict(cat_counter.most_common(8)),
        "by_host": dict(host_counter),
        "critical_samples": [dict(r) for r in sample_rows],
        "total": sum(sev_counter.values()),
    }


def _generate_ai_daily_summary(stats: dict) -> str | None:
    """未設定・失敗時はNoneを返す（呼び出し側はAI総括なしのレポートにフォールバックする）。"""
    if not (CF_AI_ACCOUNT_ID and CF_AI_GATEWAY_ID and CF_AI_TOKEN):
        return None
    url = (
        f"https://gateway.ai.cloudflare.com/v1/{CF_AI_ACCOUNT_ID}/"
        f"{CF_AI_GATEWAY_ID}/workers-ai/{CF_AI_MODEL}"
    )
    payload = {
        "messages": [
            {"role": "system", "content": DAILY_REPORT_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(stats, ensure_ascii=False)},
        ]
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {CF_AI_TOKEN}",
            "Content-Type": "application/json",
            # CloudflareのエッジがPythonの既定User-Agentをボットとしてブロックするため
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
            ),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return (body["result"]["response"] or "").strip() or None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, KeyError, TypeError):
        return None


def _build_daily_report_text(stats: dict, ai_summary: str | None, period_label: str) -> tuple[str, str]:
    sev = stats["by_severity"]
    subject = (
        f"[SENTINEL] デイリーレポート {period_label} "
        f"(CRITICAL {sev.get('critical', 0)} / WARNING {sev.get('warning', 0)})"
    )
    lines = [f"SENTINEL デイリーレポート（{period_label}）", ""]
    if ai_summary:
        lines += ["🤖 AIによる総括:", ai_summary, ""]
    lines += [
        "— 集計 —",
        f"CRITICAL: {sev.get('critical', 0)}",
        f"WARNING: {sev.get('warning', 0)}",
        f"INFO: {sev.get('info', 0)}",
        f"合計: {stats['total']}",
    ]
    if stats["by_category"]:
        lines += ["", "— カテゴリ別（上位） —"]
        lines += [f"  {cat}: {c}" for cat, c in stats["by_category"].items()]
    if stats["by_host"]:
        lines += ["", "— ホスト別（CRITICAL/WARNING） —"]
        lines += [f"  {host}: {c}" for host, c in stats["by_host"].items()]
    if stats["critical_samples"]:
        lines += ["", "— CRITICAL実例（最大10件） —"]
        lines += [
            f"  [{r['timestamp']}] {r['host']} / {r['category']}: {r['message']}"
            for r in stats["critical_samples"]
        ]
    return subject, "\n".join(lines)


def send_daily_report(is_test: bool = False) -> tuple[bool, str | None]:
    settings = _get_notify_settings()
    to_list = [a.strip() for a in settings["to"].split(",") if a.strip()]
    if not to_list:
        return False, "宛先メールアドレスが未設定です（🔔メール通知タブで設定してください）"
    if not settings["smtp_host"] and not settings["webhook_url"]:
        return False, "SMTP/Webhookのいずれも未設定です（🔔メール通知タブで設定してください）"

    now = datetime.datetime.now(JST)
    if is_test:
        end, start = now, now - datetime.timedelta(hours=24)
        period_label = "直近24時間・テスト送信"
    else:
        today0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start, end = today0 - datetime.timedelta(days=1), today0
        period_label = start.strftime("%Y-%m-%d")

    stats = _collect_period_stats(start.timestamp(), end.timestamp())
    ai_summary = _generate_ai_daily_summary(stats)
    subject, text = _build_daily_report_text(stats, ai_summary, period_label)

    try:
        if settings["smtp_host"]:
            _send_via_smtp(settings, to_list, subject, text)
        else:
            _send_via_webhook(settings["webhook_url"], to_list, subject, text, settings["from_addr"])
    except Exception as e:
        return False, str(e)
    return True, None


async def _daily_report_scheduler_loop():
    """毎分チェックし、設定時刻(JST)になったら1日1回だけデイリーレポートを送る。"""
    while True:
        try:
            settings = _get_daily_report_settings()
            if settings["enabled"]:
                now = datetime.datetime.now(JST)
                today_str = now.strftime("%Y-%m-%d")
                last_sent = _get_app_setting("daily_report_last_sent_date")
                if now.hour == settings["hour"] and last_sent != today_str:
                    ok, err = send_daily_report(is_test=False)
                    _set_app_setting("daily_report_last_sent_date", today_str)
                    if not ok:
                        print(f"[daily_report] 送信失敗: {err}")
        except Exception as e:
            print(f"[daily_report] スケジューラでエラー: {e}")
        await asyncio.sleep(60)


def _send_critical_email(record: dict, force: bool = False):
    """CRITICALアラート発生時にメール通知する。SMTP・Webhookのどちらか設定されている
    方式で送信する（両方設定されていればSMTPを優先、いずれも未設定なら何もしない）。
    ingest_alertのレスポンスをブロックしないよう、呼び出し側でBackgroundTasksとして実行する想定。
    force=Trueの場合はenabledトグルを無視して送る（設定タブの「テスト送信」用）。"""
    settings = _get_notify_settings()
    if (not force and not settings["enabled"]) or not settings["to"]:
        return
    if not settings["smtp_host"] and not settings["webhook_url"]:
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

    try:
        if settings["smtp_host"]:
            _send_via_smtp(settings, to_list, subject, text)
        else:
            _send_via_webhook(settings["webhook_url"], to_list, subject, text, settings["from_addr"])
    except Exception as e:
        # メール送信の失敗でアラート処理自体を止めない。ローカルログにだけ残す。
        print(f"[notify] メール送信に失敗: {e}")


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
            # setdefaultだとoriginal_severityが既にNoneとして存在するケース(agent側の
            # notify.pyがAI非格下げ時にNoneを送ってくる)で何もせず終わってしまうため、
            # 明示的にfalsyかどうかで判定する。
            if not record.get("original_severity"):
                record["original_severity"] = record.get("severity", "unknown")
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
            # setdefaultだとoriginal_severityが既にNoneとして存在するケース(agent側の
            # notify.pyがAI非格下げ時にNoneを送ってくる)で何もせず終わってしまうため、
            # 明示的にfalsyかどうかで判定する。
            if not record.get("original_severity"):
                record["original_severity"] = record.get("severity", "unknown")
            record["severity"] = "info"
            record["suppressed"] = True
            record["suppression_pattern"] = f"SSH許可リスト: {entry['entry']}"
            return


def _persist_important(record: dict):
    # 元々critical/warningだったもの（AIに格下げされたものも含む）を対象にする。
    # そうしないとAIが非脅威判定してinfoに格下げしたアラートが監査ログから漏れる。
    # 注意: agent側(app/notify.py)はAIが格下げしなかった場合、original_severityを
    # 明示的にNoneとして送ってくる(「格下げされた場合だけ意味を持つ値」という設計)。
    # record.get(key, default)はキーが存在すれば値(None)をそのまま返しdefaultは
    # 使われないため、素朴に書くとAIが脅威と判定して残した最重要アラートの方が
    # Noneになって保存対象から漏れる、という逆転したバグになる。
    severity = record.get("severity", "unknown")
    original_severity = record.get("original_severity") or severity
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
        record["timestamp"] = datetime.datetime.fromtimestamp(record["epoch"], JST).strftime("%Y-%m-%dT%H:%M:%S")
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
    if "webhook_url" in payload:
        _set_app_setting("webhook_url", (payload["webhook_url"] or "").strip())
    if "smtp_host" in payload:
        _set_app_setting("smtp_host", (payload["smtp_host"] or "").strip())
    if "smtp_port" in payload:
        _set_app_setting("smtp_port", str(payload["smtp_port"] or "587").strip())
    if "smtp_user" in payload:
        _set_app_setting("smtp_user", (payload["smtp_user"] or "").strip())
    if "smtp_password" in payload:
        _set_app_setting("smtp_password", payload["smtp_password"] or "")
    if "smtp_use_tls" in payload:
        _set_app_setting("smtp_use_tls", "true" if payload["smtp_use_tls"] else "false")
    return {"ok": True, "settings": _get_notify_settings()}


@app.post("/api/notify-settings/test")
async def api_test_notify_settings():
    """設定タブから「テスト送信」した際に叩くエンドポイント。実際のアラートを
    経由せず、SMTP/Webhookのどちらの通知経路が正しく動くかその場で確認できるようにする。"""
    settings = _get_notify_settings()
    if not settings["to"]:
        raise HTTPException(status_code=400, detail="宛先メールアドレスが未設定です")
    _send_critical_email({
        "host": "sentinel-test",
        "category": "test",
        "message": "これはSENTINELからのテスト通知です。この文面が届いていればmailman連携は正常です。",
        "timestamp": datetime.datetime.now(JST).strftime("%Y-%m-%dT%H:%M:%S"),
        "severity": "critical",
    }, force=True)
    return {"ok": True}


@app.get("/api/daily-report-settings")
def api_get_daily_report_settings():
    return _get_daily_report_settings()


@app.post("/api/daily-report-settings")
async def api_set_daily_report_settings(payload: dict):
    if "enabled" in payload:
        _set_app_setting("daily_report_enabled", "true" if payload["enabled"] else "false")
    if "hour" in payload:
        hour = max(0, min(23, int(payload["hour"])))
        _set_app_setting("daily_report_hour", str(hour))
    return {"ok": True, "settings": _get_daily_report_settings()}


@app.post("/api/daily-report-settings/test")
async def api_test_daily_report_settings():
    ok, err = send_daily_report(is_test=True)
    if not ok:
        raise HTTPException(status_code=400, detail=err or "送信に失敗しました")
    return {"ok": True}


@app.post("/api/ingest/status")
async def ingest_status(payload: dict, authorization: str | None = Header(default=None)):
    _check_token(authorization)
    host = payload.get("host") or "unknown"
    hosts = _read_hosts_status()
    hosts[host] = {**payload, "host": host, "received_at": time.time()}
    _write_hosts_status(hosts)
    return {"ok": True}


GITHUB_RELEASES_REPO = os.environ.get("GITHUB_RELEASES_REPO", "hit1023/sentinel")
RELEASES_CACHE_TTL = 300
_releases_cache = {"data": None, "fetched_at": 0.0}


def _fetch_github_releases() -> list[dict]:
    """公開リポジトリのGitHub Releases一覧を取得する（無認証で使える、レート制限は
    60req/h/IP程度なので、gate自身のIPからの呼び出しが集中しないようTTLキャッシュする）。"""
    now = time.time()
    if _releases_cache["data"] is not None and (now - _releases_cache["fetched_at"]) < RELEASES_CACHE_TTL:
        return _releases_cache["data"]

    url = f"https://api.github.com/repos/{GITHUB_RELEASES_REPO}/releases"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            # GitHub APIはUser-Agent未指定だと403で拒否するため明示的に付与する
            "User-Agent": "sentinel-webui",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[releases] GitHub Releases取得に失敗: {e}")
        # 直前の取得結果が残っていればそれを返し、UIを空にしない
        return _releases_cache["data"] or []

    releases = []
    for r in raw:
        if r.get("draft"):
            continue
        releases.append({
            "tag": r.get("tag_name", ""),
            "name": r.get("name") or r.get("tag_name", ""),
            "prerelease": bool(r.get("prerelease")),
            "published_at": r.get("published_at"),
            "body": r.get("body") or "",
            "assets": [
                {
                    "name": a.get("name", ""),
                    "download_url": a.get("browser_download_url", ""),
                    "size": a.get("size", 0),
                }
                for a in r.get("assets", [])
                if a.get("name", "").endswith(".tar.gz")
            ],
        })
    _releases_cache["data"] = releases
    _releases_cache["fetched_at"] = now
    return releases


@app.get("/api/releases")
def api_releases():
    return {"releases": _fetch_github_releases(), "repo": GITHUB_RELEASES_REPO}


@app.get("/api/central-config")
def api_central_config():
    """配布ページで実行コマンドを組み立てるための補助情報。
    ssh-whitelist/suppressions等と同様、このWebUI自体が無認証で操作できる前提
    （信頼されたLAN内での利用を想定）のため、共有Ingestトークンもここで返してよい。"""
    return {"ingest_token": INGEST_TOKEN}


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
    category: str | None = None,
    since_epoch: float | None = None,
):
    """CRITICAL/WARNING（元severity）だけをSQLiteから長期検索するエンドポイント。
    jsonlのtail(直近5000行)と違い、ホストのローテーション・再起動を跨いだ過去分も引ける。
    ダッシュボードのフィルタ(CRITICAL/WARNINGカード・カテゴリ)から呼ばれ、統計カードの
    件数とフィード表示の件数が食い違わないようにする。"""
    limit = min(max(limit, 1), 5000)
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if host:
        query += " AND host = ?"
        params.append(host)
    if severity:
        query += " AND (severity = ? OR original_severity = ?)"
        params.extend([severity, severity])
    if category:
        query += " AND category = ?"
        params.append(category)
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


@app.on_event("startup")
async def _on_startup():
    asyncio.create_task(_daily_report_scheduler_loop())


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
