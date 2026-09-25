"""アラート通知（中央WebUIへHTTP送信 + ローカルログ + Webhook + AIトリアージ）"""
import datetime
import json
import os
import uuid
import urllib.request
import urllib.error

import ai_triage
import central_config as central_config_mod
import paths

# コンテナはTZ設定に関わらずUTCで動くことが多いため、表示・保存する時刻は
# システムのローカルタイムに依存せずJST固定で生成する。
JST = datetime.timezone(datetime.timedelta(hours=9))


class Notifier:
    def __init__(self, config: dict, ai_triage_config: dict | None = None, central_config: dict | None = None):
        # config.get(key, default)はキーが存在すれば値(空文字含む)をそのまま返すため、
        # config.yaml側でlog_file: ""(未設定の意図)にしていてもdefaultは使われない。
        # 明示的なfalsyチェックでdata_dir()ベースのデフォルトにフォールバックさせる。
        self.log_file = config.get("log_file") or os.path.join(paths.data_dir(), "alerts.log")
        self.webhook_url = config.get("webhook_url") or None
        self.webhook_token = config.get("webhook_token") or None
        self.ai_triage_config = ai_triage_config or {}

        resolved = central_config_mod.resolve(central_config)
        self.central_enabled = resolved["enabled"]
        self.central_webui_url = resolved["webui_url"]
        self.central_token = resolved["ingest_token"]
        self.central_timeout = resolved["timeout_seconds"]
        self.host_label = resolved["host_label"]

    def alert(self, category: str, message: str, severity: str = "warning"):
        now = datetime.datetime.now(JST)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S")

        ai_summary = None
        ai_dismissed = False
        effective_severity = severity
        try:
            result = ai_triage.triage(category, severity, message, self.ai_triage_config)
        except Exception as e:  # AIトリアージの失敗で通知そのものを止めない
            result = None
            print(f"AIトリアージに失敗: {e}", flush=True)
        if result:
            ai_summary = result.comment
            auto_dismiss = ai_triage.get_config(self.ai_triage_config)["auto_dismiss_non_threats"]
            if not result.is_threat and auto_dismiss:
                effective_severity = "info"
                ai_dismissed = True

        line = f"[{ts}] [{effective_severity.upper()}] [{category}] {message}"
        if ai_dismissed:
            line += f"  (AIが非脅威と判定、元の重大度: {severity.upper()})"
        print(line, flush=True)
        if ai_summary:
            print(f"  🤖 {ai_summary}", flush=True)

        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"アラートログの書き込みに失敗: {e}", flush=True)

        record = {
            "id": uuid.uuid4().hex,
            "timestamp": ts,
            "epoch": now.timestamp(),
            "host": self.host_label,
            "category": category,
            "severity": effective_severity,
            "original_severity": severity if ai_dismissed else None,
            "message": message,
            "ai_summary": ai_summary,
            "ai_dismissed": ai_dismissed,
        }

        if self.central_enabled and self.central_webui_url:
            self._send_central(record)

        # AIが非脅威と判定して静かにしたものはWebhook(LINE/Push等)へは飛ばさない
        if self.webhook_url and not ai_dismissed:
            self._send_webhook(record)

    def _send_central(self, record: dict):
        url = f"{self.central_webui_url}/api/ingest/alert"
        data = json.dumps(record, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.central_token:
            headers["Authorization"] = f"Bearer {self.central_token}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.central_timeout) as resp:
                resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"中央WebUIへの送信に失敗: {e}", flush=True)

    def _send_webhook(self, record: dict):
        payload = {"source": "hit-linux-ids", **record}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.webhook_token:
            headers["Authorization"] = f"Bearer {self.webhook_token}"
        req = urllib.request.Request(self.webhook_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"Webhook通知に失敗: {e}", flush=True)
