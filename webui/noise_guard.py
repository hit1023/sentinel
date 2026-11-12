"""WARNINGの洪水を防ぐ（オオカミ少年対策）。

誤検知が大量に出ると、本物の警告が埋もれて誰も見なくなる。エージェントの更新を待たずに
全ホストへ効かせるため、マネージャーが受け取る時点で次の2段で抑える。CRITICALは対象外で、
必ずそのまま通す。

  1. 同じ内容の再発: 同じホスト・同じ種類・同じ内容（pid等の数字を除いて同一）のWARNINGが
     一定時間内にもう一度来たら、2回目以降はINFOに格下げする（最初の1件は通す）。
  2. 件数の上限: 同じホスト・同じ種類のWARNINGが1時間に上限を超えたら、超過分はINFOに格下げし、
     「ノイズ源の可能性」を1時間に1回だけWARNINGで知らせる。

セキュリティ上の信号そのものである認証ログ(auth_watch)・Webアクセス(web_watch)等は
対象外（GUARDED_CATEGORIESに含まれるものだけを抑える）。格下げしても元の重大度
（original_severity）は残るので、監査ログからは辿れる。
"""
import re
import threading
import time

# 誤検知で洪水になりやすい『状態の変化を拾う』種類だけを対象にする
GUARDED_CATEGORIES = ("procnet_watch", "integrity_watch", "outbound_watch")
DEDUPE_WINDOW_SECONDS = 6 * 3600
BUDGET_PER_HOUR = 20
BUDGET_WINDOW_SECONDS = 3600
_MAX_TRACKED_KEYS = 5000

_DIGITS_RE = re.compile(r"\d+")


def normalize_message(message: str) -> str:
    """pidやポート番号など、同じ事象でも毎回変わる数字をNに潰して比較できる形にする。"""
    return _DIGITS_RE.sub("N", message or "")[:200]


class NoiseGuard:
    def __init__(self, categories=GUARDED_CATEGORIES, dedupe_window=DEDUPE_WINDOW_SECONDS,
                 budget=BUDGET_PER_HOUR, budget_window=BUDGET_WINDOW_SECONDS, clock=time.time):
        self.categories = tuple(categories)
        self.dedupe_window = dedupe_window
        self.budget = budget
        self.budget_window = budget_window
        self._clock = clock
        self._lock = threading.Lock()
        self._seen = {}      # (host, category, 正規化した内容) -> 最後に通した時刻
        self._passed = {}    # (host, category) -> 通したWARNINGの時刻リスト
        self._notified = {}  # (host, category) -> 最後にノイズ源の通知を出した時刻

    def apply(self, record: dict):
        """recordを必要ならINFOへ格下げする（その場で書き換える）。ノイズ源の通知を出すべき
        ときだけ、通知として流すアラート（辞書）を返す。それ以外はNone。"""
        if (record.get("severity") or "").lower() != "warning":
            return None
        category = record.get("category")
        if category not in self.categories:
            return None
        host = record.get("host") or "unknown"
        now = self._clock()
        key = (host, category, normalize_message(record.get("message")))
        pair = (host, category)
        notice = None
        with self._lock:
            self._prune(now)
            last = self._seen.get(key)
            if last is not None and now - last < self.dedupe_window:
                self._downgrade(record, "同じ内容の再発")
                return None
            recent = [t for t in self._passed.get(pair, []) if now - t < self.budget_window]
            if len(recent) >= self.budget:
                self._passed[pair] = recent
                self._downgrade(record, "1時間あたりの件数上限を超過")
                if now - self._notified.get(pair, 0) >= self.budget_window:
                    self._notified[pair] = now
                    notice = {
                        "category": "noise_guard",
                        "host": host,
                        "severity": "warning",
                        "message": (
                            f"{host} の {category} の警告が1時間に{self.budget}件を超えました。"
                            "誤検知などのノイズ源の可能性があります。超過分はINFOに格下げし、個別の通知は止めています。"
                            "頻出する内容は除外ルール（または既知プロセス）に登録してください"
                        ),
                    }
                return notice
            recent.append(now)
            self._passed[pair] = recent
            self._seen[key] = now
        return None

    @staticmethod
    def _downgrade(record: dict, reason: str):
        # original_severityがNoneとして既に存在するケースがあるため、falsyかどうかで判定する
        if not record.get("original_severity"):
            record["original_severity"] = record.get("severity", "warning")
        record["severity"] = "info"
        record["noise_guard"] = reason

    def _prune(self, now: float):
        if len(self._seen) > _MAX_TRACKED_KEYS:
            self._seen = {k: t for k, t in self._seen.items() if now - t < self.dedupe_window}
        if len(self._passed) > _MAX_TRACKED_KEYS:
            self._passed = {k: v for k, v in self._passed.items() if v and now - v[-1] < self.budget_window}
