"""ATTACK MAP（世界地図上に攻撃元→自宅の線を描くパネル）用のデータ集計。

対象は外部からの攻撃とみなせるアラートだけ:
  - auth_watch: ログイン失敗・ブルートフォース・存在しないユーザー等（通常のログイン成功は除外。
    「いつもと異なるロケーションからのログイン成功」は不審なので別種として含める）
  - web_watch: Webアクセス異常（スキャン・パストラバーサル等）
アラート本文からIPを抜き出し、ip-api.com（agentのgeoip.pyと同じ無料API）で緯度経度を引いて
SQLiteにキャッシュする。プライベートIP（LAN内）は地図に載せる意味がないので対象外。
"""
import ipaddress
import json
import os
import re
import time
import urllib.request

IP_RE = re.compile(r"from=([0-9a-fA-F:.]+)|疑い: ([0-9a-fA-F:.]+) から|ip=([0-9a-fA-F:.]+)")
# ip-api.comのbatchは1リクエスト100件まで・無料枠は毎分15リクエストまで
GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,query,lat,lon,country,countryCode,city&lang=ja"
GEO_BATCH_SIZE = 100
# 1回のAPI呼び出し（=ダッシュボードの1ポーリング）で問い合わせるbatch数の上限。
# 未解決が多くても、残りは次回以降のポーリングで少しずつ解決する（レート制限を超えないため）
GEO_MAX_BATCHES_PER_CALL = 3
# 失敗(取得不可)したIPは毎回問い合わせ直さないよう、この秒数は再試行しない
GEO_RETRY_FAILED_AFTER = 24 * 3600

# 攻撃先（自宅）の位置。既定は東京。ATTACK_MAP_HOME="緯度,経度,表示名" で変更できる
_home = (os.environ.get("ATTACK_MAP_HOME") or "35.68,139.69,TOKYO").split(",")
HOME = {"lat": float(_home[0]), "lon": float(_home[1]), "label": _home[2] if len(_home) > 2 else "HOME"}


def init_db(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY,
            ok INTEGER,
            lat REAL,
            lon REAL,
            country TEXT,
            country_code TEXT,
            city TEXT,
            fetched_at REAL
        )
        """
    )


def classify(record: dict) -> tuple[str, str] | None:
    """攻撃として地図に載せるアラートなら (ip, kind) を返す。kind: ssh / web / login"""
    category = record.get("category")
    message = record.get("message") or ""
    if category == "auth_watch":
        if message.startswith("ログイン成功"):
            return None  # 普段のログイン（自分自身）は攻撃ではない
        kind = "login" if "ログイン成功" in message else "ssh"
    elif category == "web_watch":
        kind = "web"
    else:
        return None
    m = IP_RE.search(message)
    if not m:
        return None
    ip = next(g for g in m.groups() if g)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return None
    return ip, kind


class AttackMap:
    def __init__(self, connect):
        self.connect = connect
        with self.connect() as conn:
            init_db(conn)

    def _geo(self, ips: set[str]) -> dict[str, dict]:
        """キャッシュ済みの位置情報を返し、未解決のものは上限内でAPIに問い合わせる。"""
        now = time.time()
        with self.connect() as conn:
            rows = {
                r["ip"]: dict(r)
                for r in conn.execute("SELECT * FROM geo_cache").fetchall()
                if r["ip"] in ips
            }
        todo = [
            ip for ip in ips
            if ip not in rows or (not rows[ip]["ok"] and now - rows[ip]["fetched_at"] > GEO_RETRY_FAILED_AFTER)
        ]
        for i in range(0, min(len(todo), GEO_BATCH_SIZE * GEO_MAX_BATCHES_PER_CALL), GEO_BATCH_SIZE):
            batch = todo[i:i + GEO_BATCH_SIZE]
            try:
                req = urllib.request.Request(
                    GEO_BATCH_URL,
                    data=json.dumps(batch).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "sentinel-ids/1.0"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    results = json.loads(resp.read().decode("utf-8"))
            except Exception as e:  # 位置情報が取れなくても地図以外の機能には影響させない
                print(f"[attackmap] 位置情報の取得に失敗: {e}")
                break
            fetched = []
            for r in results:
                ok = r.get("status") == "success"
                fetched.append((
                    r.get("query"), 1 if ok else 0, r.get("lat"), r.get("lon"),
                    r.get("country") or "", r.get("countryCode") or "", r.get("city") or "", now,
                ))
            with self.connect() as conn:
                conn.executemany("INSERT OR REPLACE INTO geo_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?)", fetched)
            for row in fetched:
                rows[row[0]] = {
                    "ip": row[0], "ok": row[1], "lat": row[2], "lon": row[3],
                    "country": row[4], "country_code": row[5], "city": row[6],
                }
        return {ip: g for ip, g in rows.items() if g["ok"]}

    def _events(self, records: list[dict]) -> list[dict]:
        events = []
        for r in records:
            hit = classify(r)
            if not hit:
                continue
            events.append({
                "id": r.get("id"),
                "epoch": r.get("epoch"),
                "ip": hit[0],
                "kind": hit[1],
                "host": r.get("host"),
                "severity": r.get("original_severity") or r.get("severity"),
            })
        return events

    def build(self, records: list[dict], max_events: int = 400) -> dict:
        """records: 期間内のアラート（古い順）。地図描画用に、攻撃元IPごとの集計と直近イベントを返す。"""
        events = self._events(records)
        geo = self._geo({e["ip"] for e in events})

        sources: dict[str, dict] = {}
        countries: dict[str, dict] = {}
        located = []
        for e in events:
            g = geo.get(e["ip"])
            if not g:
                continue
            e = {**e, "lat": g["lat"], "lon": g["lon"], "country": g["country"],
                 "cc": g["country_code"], "city": g["city"]}
            located.append(e)
            s = sources.setdefault(e["ip"], {
                "ip": e["ip"], "lat": e["lat"], "lon": e["lon"], "country": e["country"],
                "cc": e["cc"], "city": e["city"], "count": 0, "kinds": {}, "hosts": [], "last_epoch": 0,
            })
            s["count"] += 1
            s["kinds"][e["kind"]] = s["kinds"].get(e["kind"], 0) + 1
            if e["host"] and e["host"] not in s["hosts"]:
                s["hosts"].append(e["host"])
            s["last_epoch"] = max(s["last_epoch"], e["epoch"] or 0)
            c = countries.setdefault(e["cc"] or e["country"], {"cc": e["cc"], "country": e["country"], "count": 0, "ips": set()})
            c["count"] += 1
            c["ips"].add(e["ip"])

        top_countries = sorted(countries.values(), key=lambda c: -c["count"])[:10]
        return {
            "home": HOME,
            "sources": sorted(sources.values(), key=lambda s: -s["count"])[:500],
            "events": located[-max_events:],
            "top_countries": [
                {"cc": c["cc"], "country": c["country"], "count": c["count"], "ips": len(c["ips"])}
                for c in top_countries
            ],
            "total_events": len(events),
            "located_events": len(located),
            "unique_ips": len({e["ip"] for e in events}),
        }
