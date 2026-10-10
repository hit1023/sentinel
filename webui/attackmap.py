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
# outbound_watch: 「…: 203.0.113.9:4444 pid=…」の宛先IP（自ホストから外へ出る通信）
OUTBOUND_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5} pid=")
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


# 攻撃が「防げなかった」(シールドを貫通する)種類。HUDのBREACH件数の対象
BREACH_KINDS = ("login", "webbreach", "outbound")
SCOPE_CATEGORIES = {
    "ssh": ("auth_watch",),
    "web": ("web_watch",),
    "out": ("outbound_watch",),
}
ALL_CATEGORIES = ("auth_watch", "web_watch", "outbound_watch")


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
    """攻撃として地図に載せるアラートなら (ip, kind) を返す。
    kind: ssh / web / login（不審ログイン成功）/ webbreach（Webで機密パス等に成功応答が返った）/
          outbound（自ホストから外へ出る不審な通信。C2・情報持ち出しの疑い。IPは宛先）"""
    category = record.get("category")
    message = record.get("message") or ""
    if category == "auth_watch":
        if message.startswith("ログイン成功"):
            return None  # 普段のログイン（自分自身）は攻撃ではない
        kind = "login" if "ログイン成功" in message else "ssh"
    elif category == "outbound_watch":
        m = OUTBOUND_RE.search(message)
        if not m:
            return None
        ip, kind = m.group(1), "outbound"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return None
        return ip, kind
    elif category == "web_watch":
        # 機密パス等への2xx応答は「防げていない」攻撃。SSHの不審ログイン成功と同様にシールドを貫通させる
        kind = "webbreach" if "成功応答" in message else "web"
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


def build_hud(records: list[dict], critical_1h: int, hosts: list[dict], kev_open: int, now: float | None = None) -> dict:
    """HUD（目で即座に状況を把握するための要約）。records: 直近24時間の攻撃系アラート。
    脅威レベル: RED = 直近6時間に防げなかった攻撃(不審ログイン成功/Web成功応答/不審な外向き通信)
    または直近1時間にCRITICAL / AMBER = オフライン・KEV入り脆弱性・24時間内のCRITICALあり / GREEN = それ以外"""
    now = now or time.time()
    attacks = {"ssh": 0, "web": 0, "out": 0}
    breaches_6h = 0
    for r in records:
        hit = classify(r)
        if not hit:
            continue
        kind = hit[1]
        attacks["ssh" if kind in ("ssh", "login") else "out" if kind == "outbound" else "web"] += 1
        if kind in BREACH_KINDS and (r.get("epoch") or 0) > now - 6 * 3600:
            breaches_6h += 1
    online = sum(1 for h in hosts if h.get("online"))
    offline = [h.get("host") for h in hosts if not h.get("online")]
    reasons = []
    level = "green"
    if breaches_6h:
        level = "red"
        reasons.append(f"防げなかった攻撃が直近6時間に{breaches_6h}件")
    if critical_1h:
        level = "red"
        reasons.append(f"直近1時間にCRITICAL {critical_1h}件")
    if level != "red":
        if offline:
            level = "amber"
            reasons.append(f"応答なしのホスト: {', '.join(map(str, offline[:3]))}")
        if kev_open:
            level = "amber"
            reasons.append(f"悪用確認済み(KEV)の脆弱性 {kev_open}件が未解消")
    return {
        "level": level, "reasons": reasons, "attacks_24h": attacks, "breaches_6h": breaches_6h,
        "critical_1h": critical_1h, "hosts_online": online, "hosts_total": len(hosts), "kev_open": kev_open,
    }


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
