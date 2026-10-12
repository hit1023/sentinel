"""AbuseIPDB（https://www.abuseipdb.com/）への攻撃元IPの通報。

通報は外部に出る操作なので、SENTINELは「候補を出す」ところまでを自動で行い、送信は人が確認して押した時だけ行う。
送るのは、攻撃元のIP・種類のカテゴリ・自分のホスト名等を含まない短いコメント・時刻だけ。
"""
import json
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.abuseipdb.com/api/v2"
# AbuseIPDBのカテゴリ: 18=Brute-Force, 22=SSH, 21=Web App Attack
CATEGORIES = {"ssh": (18, 22), "web": (21,)}
DEFAULT_MIN_EVENTS = 5
MAX_REPORTS_PER_DAY = 50  # 誤操作・連打による大量送信の歯止め（無料枠は1日1,000件）


def categories_for(kinds: dict) -> list[int]:
    out = set()
    for k in kinds:
        out.update(CATEGORIES.get(k, ()))
    return sorted(out)


def build_comment(count: int, kinds: dict, hours: int = 24) -> str:
    parts = []
    if kinds.get("ssh"):
        parts.append(f"{kinds['ssh']} failed SSH login attempts")
    if kinds.get("web"):
        parts.append(f"{kinds['web']} suspicious web requests (scanner/exploit patterns)")
    return f"Detected by SENTINEL (self-hosted IDS): {' and '.join(parts)} within {hours}h."


def _request(path: str, key: str, data: dict | None = None, timeout: float = 15):
    url = f"{API}{path}"
    headers = {"Key": key, "Accept": "application/json", "User-Agent": "sentinel-ids/1.0"}
    if data is None:
        req = urllib.request.Request(url, headers=headers)
    else:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("errors", [{}])[0].get("detail", "")
        except Exception:
            detail = ""
        raise RuntimeError(f"AbuseIPDB {e.code}: {detail or e.reason}") from None


def check_key(key: str) -> dict:
    """キーが有効かを、テスト用IP(127.0.0.2)の照会で確認する（通報はしない）。"""
    data, headers = _request(f"/check?ipAddress=127.0.0.2&maxAgeInDays=1", key)
    return {"ok": True, "remaining": headers.get("X-RateLimit-Remaining"), "limit": headers.get("X-RateLimit-Limit")}


def report_ip(key: str, ip: str, categories: list[int], comment: str, timestamp_iso: str) -> dict:
    data, _ = _request("/report", key, {
        "ip": ip, "categories": ",".join(map(str, categories)), "comment": comment[:1000], "timestamp": timestamp_iso,
    })
    return data.get("data", {})


def check_ip(key: str, ip: str, timeout: float = 15) -> dict:
    """IPの評判を照会する（読み取りだけ。通報はしない）。"""
    data, _ = _request(f"/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90", key, timeout=timeout)
    d = data.get("data", {})
    return {
        "score": int(d.get("abuseConfidenceScore") or 0),
        "reports": int(d.get("totalReports") or 0),
        "usage": d.get("usageType") or "",
        "isp": d.get("isp") or "",
    }
