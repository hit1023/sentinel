"""Cloudflare AI Gateway経由でアラートを即時トリアージ（日本語1〜2文の要約＋危険度）する"""
import json
import os
import urllib.error
import urllib.request

SYSTEM_PROMPT = (
    "あなたはLinuxサーバーのセキュリティ監視を担当するSOCアナリストです。"
    "渡されたアラート(カテゴリ・重大度・メッセージ)を見て、"
    "日本語で1〜2文、40〜80文字程度の簡潔なトリアージコメントを書いてください。"
    "含めるべき要素: 何が起きたかの平易な説明、緊急度の所感、次に確認すべきことがあれば一言。"
    "誇張・断定は避け、断片的な情報からの推測であることを踏まえた慎重な言い回しにしてください。"
    "前置き・見出し・箇条書き記号は付けず、本文の日本語のみを出力してください。"
)


def get_config(cfg: dict) -> dict:
    return {
        "enabled": cfg.get("enabled", False),
        "trigger_severities": set(cfg.get("trigger_severities", ["critical", "warning"])),
        "account_id": cfg.get("cloudflare_account_id", ""),
        "gateway_id": cfg.get("cloudflare_gateway_id", ""),
        "model": cfg.get("model", "@cf/meta/llama-3.1-8b-instruct-fast"),
        "api_token": cfg.get("api_token") or os.environ.get("CF_AI_GATEWAY_TOKEN", ""),
        "timeout_seconds": cfg.get("timeout_seconds", 8),
    }


def should_triage(severity: str, cfg: dict) -> bool:
    ai_cfg = get_config(cfg)
    if not ai_cfg["enabled"]:
        return False
    if not ai_cfg["account_id"] or not ai_cfg["gateway_id"] or not ai_cfg["api_token"]:
        return False
    return severity.lower() in ai_cfg["trigger_severities"]


def summarize(category: str, severity: str, message: str, cfg: dict) -> str | None:
    """Cloudflare AI GatewayのWorkers AIエンドポイントへ問い合わせ、要約文字列を返す。
    失敗時（未設定・タイムアウト・APIエラー等）は何も投げずNoneを返す。"""
    ai_cfg = get_config(cfg)
    if not should_triage(severity, cfg):
        return None

    url = (
        f"https://gateway.ai.cloudflare.com/v1/{ai_cfg['account_id']}/"
        f"{ai_cfg['gateway_id']}/workers-ai/{ai_cfg['model']}"
    )
    payload = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"category={category}\nseverity={severity}\nmessage={message}",
            },
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {ai_cfg['api_token']}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=ai_cfg["timeout_seconds"]) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    try:
        text = body["result"]["response"]
    except (KeyError, TypeError):
        return None

    text = (text or "").strip()
    return text or None
