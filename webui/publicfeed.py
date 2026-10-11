"""公開用の脅威フィード（s-quad.com等に載せる）。

内部のアラートから、外部に出して差し支えない情報だけを集計して返す:
  - 攻撃元IPは一部を伏せる（IPv4は下位8bit、IPv6は下位80bit）。誤検知・踏み台にされた無関係なサーバーを晒さない。
  - 出すのは国・ネットワーク名(ASN)・種類(ssh/web)・回数・時刻（1時間単位）だけ。
  - 直近1時間は出さない（リアルタイムの手がかりを与えない）。24時間分を遅れて出す。
  - 自分のホスト名・成功したログイン・Webでの成功応答・外向き通信・どのサービスが狙われたかは一切出さない。
  - 確度の高いもの（一定回数以上、研究目的のスキャナーを除く）だけを出す。
"""
import ipaddress
import json
import time
import urllib.request

DELAY_SECONDS = 3600
WINDOW_HOURS = 24
MIN_EVENTS = 3          # この回数に満たない発信元は載せない（偶発的なアクセス・誤検知を避ける）
MAX_ITEMS = 30
PUBLIC_KINDS = ("ssh", "web")
# 研究・調査目的で広くスキャンしている組織。攻撃者として晒さない
BENIGN_SCANNER_ORGS = (
    "censys", "shodan", "shadowserver", "binaryedge", "internet census", "recyber", "stretchoid",
    "palo alto", "driftnet", "onyphe", "leakix", "netcraft", "alphastrike", "projectdiscovery", "cyble",
)
ASN_URL = "http://ip-api.com/batch?fields=status,query,as,asname,org"
ASN_RETRY_FAILED_AFTER = 24 * 3600


def mask_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        a, b, c, _ = ip.split(".")
        return f"{a}.{b}.{c}.x"
    parts = addr.exploded.split(":")
    return ":".join(parts[:3]).lstrip("0") + "::x"


def init_db(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS asn_cache (ip TEXT PRIMARY KEY, ok INTEGER, asn TEXT, name TEXT, org TEXT, fetched_at REAL)")


def lookup_asn(connect, ips: set[str], max_batches: int = 2) -> dict[str, dict]:
    """IPごとのASN・ネットワーク名。キャッシュ済みを返し、未解決は上限内でAPIへ問い合わせる。"""
    now = time.time()
    with connect() as conn:
        init_db(conn)
        rows = {r["ip"]: dict(r) for r in conn.execute("SELECT * FROM asn_cache").fetchall() if r["ip"] in ips}
    todo = [ip for ip in ips if ip not in rows or (not rows[ip]["ok"] and now - rows[ip]["fetched_at"] > ASN_RETRY_FAILED_AFTER)]
    for i in range(0, min(len(todo), 100 * max_batches), 100):
        batch = todo[i:i + 100]
        try:
            req = urllib.request.Request(ASN_URL, data=json.dumps(batch).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "User-Agent": "sentinel-ids/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read().decode())
        except Exception as e:  # ASNが取れなくてもフィード自体は出せる
            print(f"[publicfeed] ASNの取得に失敗: {e}")
            break
        fetched = []
        for r in results:
            ok = r.get("status") == "success"
            asn = (r.get("as") or "").split(" ")[0]
            fetched.append((r.get("query"), 1 if ok else 0, asn, r.get("asname") or "", r.get("org") or "", now))
        with connect() as conn:
            conn.executemany("INSERT OR REPLACE INTO asn_cache VALUES (?, ?, ?, ?, ?, ?)", fetched)
        for f in fetched:
            rows[f[0]] = {"ip": f[0], "ok": f[1], "asn": f[2], "name": f[3], "org": f[4]}
    return {ip: r for ip, r in rows.items() if r.get("ok")}


def is_benign_scanner(asn_info: dict | None) -> bool:
    text = f"{(asn_info or {}).get('name', '')} {(asn_info or {}).get('org', '')}".lower()
    return any(s in text for s in BENIGN_SCANNER_ORGS)


def build(events: list[dict], geo: dict[str, dict], asn: dict[str, dict], now: float | None = None) -> dict:
    """events: attackmap._events()の出力（ip/kind/epoch）。geo: ip→位置情報、asn: ip→ASN情報。"""
    now = now or time.time()
    end = now - DELAY_SECONDS
    start = end - WINDOW_HOURS * 3600
    per_ip: dict[str, dict] = {}
    for e in events:
        if e["kind"] not in PUBLIC_KINDS or not (start <= (e["epoch"] or 0) < end):
            continue
        s = per_ip.setdefault(e["ip"], {"count": 0, "kinds": {}, "last": 0})
        s["count"] += 1
        s["kinds"][e["kind"]] = s["kinds"].get(e["kind"], 0) + 1
        s["last"] = max(s["last"], e["epoch"])

    items, by_country, by_kind = [], {}, {"ssh": 0, "web": 0}
    hourly = [0] * WINDOW_HOURS
    for ip, s in per_ip.items():
        g = geo.get(ip)
        if not g or s["count"] < MIN_EVENTS or is_benign_scanner(asn.get(ip)):
            continue
        a = asn.get(ip) or {}
        items.append({
            "_ip": ip,
            "ip": mask_ip(ip),
            "cc": g["country_code"], "country": g["country"],
            # 位置は都市単位の粗い座標（小数1桁≒10km）にとどめる
            "lat": round(g["lat"], 1), "lon": round(g["lon"], 1),
            "asn": a.get("asn", ""), "network": a.get("name", ""),
            "count": s["count"], "kinds": s["kinds"],
            "last_seen": time.strftime("%Y-%m-%dT%H:00:00Z", time.gmtime(s["last"])),
        })
        c = by_country.setdefault(g["country_code"], {"cc": g["country_code"], "country": g["country"], "count": 0, "sources": 0})
        c["count"] += s["count"]
        c["sources"] += 1
        for k, n in s["kinds"].items():
            by_kind[k] += n
    shown = {i["_ip"] for i in items}
    for e in events:
        if e["ip"] in shown and e["kind"] in PUBLIC_KINDS and start <= (e["epoch"] or 0) < end:
            hourly[min(WINDOW_HOURS - 1, int((e["epoch"] - start) // 3600))] += 1
    items.sort(key=lambda i: -i["count"])
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:00Z", time.gmtime(now)),
        "delay_minutes": DELAY_SECONDS // 60,
        "window_hours": WINDOW_HOURS,
        "totals": {"events": sum(by_kind.values()), "sources": len(items), "countries": len(by_country), "by_kind": by_kind},
        "countries": sorted(by_country.values(), key=lambda c: -c["count"])[:10],
        "hourly": hourly,
        "sources": [{k: v for k, v in i.items() if k != "_ip"} for i in items[:MAX_ITEMS]],
    }
