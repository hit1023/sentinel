"""IPアドレスから大まかな位置情報（国・都市）と逆引きドメインを取得するヘルパー。
外部APIキー不要のip-api.com（無料枠、認証不要）を使用し、結果はファイルにキャッシュして
同じIPへの問い合わせを繰り返さないようにする（レート制限対策・高速化の両方が目的）。"""
import ipaddress
import json
import os
import socket
import urllib.request

CACHE_PATH = "/data/geoip_cache.json"
_cache = None


def _load_cache() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                _cache = json.load(f)
                return _cache
        except (OSError, json.JSONDecodeError):
            pass
    _cache = {}
    return _cache


def _save_cache():
    if _cache is None:
        return
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    tmp_path = CACHE_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(_cache, f, ensure_ascii=False)
    os.replace(tmp_path, CACHE_PATH)


def _reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(3)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def _is_lan(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def lookup(ip: str) -> dict:
    """{"country": "日本", "city": "Tokyo", "domain": "xxx.example.com"} を返す。
    取得できなかった項目は空文字。プライベートIP（社内LANからのアクセス）は
    外部APIに問い合わせる意味がないため常に空文字を返す。"""
    if _is_lan(ip):
        return {"country": "", "city": "", "domain": ""}

    cache = _load_cache()
    if ip in cache:
        return cache[ip]

    result = {"country": "", "city": "", "domain": ""}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city&lang=ja"
        req = urllib.request.Request(url, headers={"User-Agent": "sentinel-ids/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            result["country"] = data.get("country", "")
            result["city"] = data.get("city", "")
    except Exception:
        pass

    result["domain"] = _reverse_dns(ip)

    cache[ip] = result
    _save_cache()
    return result


def format_location(info: dict) -> str:
    parts = [p for p in (info.get("country"), info.get("city")) if p]
    loc = "/".join(parts) if parts else "不明"
    domain = info.get("domain")
    return f"{loc} ({domain})" if domain else loc
