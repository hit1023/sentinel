"""悪質な攻撃元IPの自動ブロック（fail2ban連携）。

マネージャー(WebUI)は、gateのfail2banを直接は操作できない（コンテナの中にいるため）。代わりに、
ブロック対象を「SENTINEL-BAN <IP> ...」という行としてログファイルに追記する。gateのfail2banは、このファイルを
監視する専用のjail(sentinel-abuse)を持ち、追記された行のIPをiptablesで一定時間ブロックする。

ブロックするのは、次をすべて満たすIPだけ:
  - 直近1時間に、自分へのSSH攻撃（失敗の繰り返し）が一定回数以上ある（実際に攻撃してきている）
  - AbuseIPDBの信頼度が閾値（既定90%）以上（世界中で悪質と報告されている）
  - LAN内・SSH許可リスト・過去にログインに成功したことのあるIPではない（自分を締め出さない）
"""
import ipaddress
import time

DEFAULT_MIN_SCORE = 90
DEFAULT_MIN_EVENTS = 3
MAX_NEW_PER_RUN = 20       # 1回の実行で新しくブロックする最大数（誤動作時の被害を抑える）
MAX_ACTIVE = 300           # 同時にブロック中の最大数
BAN_SECONDS = 24 * 3600
MODES = ("off", "dryrun", "on")


def ban_line(ip: str, score: int, events: int, now: float, tz) -> str:
    import datetime
    ts = datetime.datetime.fromtimestamp(now, tz).strftime("%Y-%m-%dT%H:%M:%S%z")
    return f"{ts} SENTINEL-BAN {ip} score={score} events={events}\n"


def in_whitelist(ip: str, entries: list[str]) -> bool:
    """SSH許可リストのIP/CIDRに含まれるか（国名の項目は無視する）。"""
    addr = ipaddress.ip_address(ip)
    for e in entries:
        try:
            if "/" in e:
                if addr in ipaddress.ip_network(e, strict=False):
                    return True
            elif addr == ipaddress.ip_address(e):
                return True
        except ValueError:
            continue  # 国名などIP/CIDRでない項目
    return False


def pick_targets(counts: dict[str, int], *, min_events: int, whitelist: list[str], known_good: set[str],
                 already: set[str], limit: int) -> list[str]:
    """攻撃回数の多い順に、ブロック対象になり得るIP（評判の照会前）を返す。"""
    out = []
    for ip, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        if n < min_events or ip in known_good or ip in already:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            continue
        if in_whitelist(ip, whitelist):
            continue
        out.append(ip)
        if len(out) >= limit:
            break
    return out


def mask(ip: str) -> str:
    """通知・画面用に下位を伏せる（アラートはSlack/メールにも流れるため）。"""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(ip.split(".")[:3]) + ".x"
    return ":".join(addr.exploded.split(":")[:3]) + "::x"
