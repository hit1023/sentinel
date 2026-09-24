"""hit-linux-ids WebUI: エージェントが書き出す /data配下のファイルを読み、
REST + WebSocketでリアルタイムにダッシュボードへ配信する"""
import asyncio
import json
import os
import time
from collections import Counter

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

DATA_DIR = os.environ.get("IDS_DATA_DIR", "/data")
ALERTS_JSONL = os.path.join(DATA_DIR, "alerts.jsonl")
STATUS_JSON = os.path.join(DATA_DIR, "status.json")

app = FastAPI(title="hit-linux-ids WebUI")


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


def _read_status():
    if not os.path.exists(STATUS_JSON):
        return {}
    try:
        with open(STATUS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


@app.get("/api/alerts")
def api_alerts(limit: int = 200):
    return {"alerts": list(reversed(_read_alerts(limit)))}


@app.get("/api/stats")
def api_stats():
    alerts = _read_alerts(2000)
    now = time.time()
    last_24h = [a for a in alerts if now - a.get("epoch", 0) <= 86400]
    sev_counter = Counter(a.get("severity", "unknown") for a in last_24h)
    cat_counter = Counter(a.get("category", "unknown") for a in last_24h)
    status = _read_status()
    return {
        "status": status,
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
