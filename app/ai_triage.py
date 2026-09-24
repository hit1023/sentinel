"""Cloudflare AI Gateway経由でアラートを即時トリアージする。
日本語コメントの生成に加え、AIが「脅威ではない」と判断した場合は
呼び出し側で重大度を下げて通知を静かにできるよう、脅威判定も返す。"""
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

SYSTEM_PROMPT = (
    "あなたはLinuxサーバーのセキュリティ監視を担当するSOCアナリストです。"
    "渡されたアラート(カテゴリ・重大度・メッセージ)を見て、脅威かどうかを判定してください。"
    "\n"
    "出力は必ず以下の2行ちょうどの形式にしてください（前置き・見出し・箇条書き記号は禁止）:\n"
    "THREAT: YES または THREAT: NO\n"
    "続けて日本語で1〜2文、40〜80文字程度のトリアージコメント（何が起きたかの平易な説明、"
    "緊急度の所感、次に確認すべきことがあれば一言）\n"
    "\n"
    "THREAT: NO にしてよいのは、既知の正常なシステム挙動・開発/運用作業に由来する誤検知だと"
    "高い確度で判断できる場合のみです（例: known_process_keywordsに載っていないだけの"
    "docker関連プロセス、sleepコマンド、ビルド/デプロイ由来の一時プロセス等）。"
    "少しでも悪意・侵害の可能性が拭えない場合は必ず THREAT: YES としてください。"
    "誇張・断定は避け、断片的な情報からの推測であることを踏まえた慎重な言い回しにしてください。"
)


@dataclass
class TriageResult:
    is_threat: bool
    comment: str | None


def get_config(cfg: dict) -> dict:
    return {
        "enabled": cfg.get("enabled", False),
        "trigger_severities": set(cfg.get("trigger_severities", ["critical", "warning"])),
        "account_id": cfg.get("cloudflare_account_id", ""),
        "gateway_id": cfg.get("cloudflare_gateway_id", ""),
        "model": cfg.get("model", "@cf/meta/llama-3.1-8b-instruct-fast"),
        "api_token": cfg.get("api_token") or os.environ.get("CF_AI_GATEWAY_TOKEN", ""),
        "timeout_seconds": cfg.get("timeout_seconds", 8),
        "auto_dismiss_non_threats": cfg.get("auto_dismiss_non_threats", False),
    }


def should_triage(severity: str, cfg: dict) -> bool:
    ai_cfg = get_config(cfg)
    if not ai_cfg["enabled"]:
        return False
    if not ai_cfg["account_id"] or not ai_cfg["gateway_id"] or not ai_cfg["api_token"]:
        return False
    return severity.lower() in ai_cfg["trigger_severities"]


def _parse_response(text: str) -> TriageResult:
    """1行目の THREAT: YES/NO を読み取り、残りをコメントとして扱う。
    判定できない場合は安全側(is_threat=True、通知を消さない)に倒す。"""
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    if not lines:
        return TriageResult(is_threat=True, comment=None)

    first = lines[0].upper()
    if first.startswith("THREAT:"):
        verdict = first.split(":", 1)[1].strip()
        is_threat = not verdict.startswith("NO")
        comment = " ".join(lines[1:]).strip() or None
        return TriageResult(is_threat=is_threat, comment=comment)

    # 期待した形式で返ってこなかった場合は、全文をコメント扱いにしつつ
    # 脅威判定は安全側(True)に倒す
    return TriageResult(is_threat=True, comment=" ".join(lines).strip() or None)


def triage(category: str, severity: str, message: str, cfg: dict) -> TriageResult | None:
    """Cloudflare AI GatewayのWorkers AIエンドポイントへ問い合わせ、
    脅威判定(is_threat)とトリアージコメントを返す。
    失敗時（未設定・タイムアウト・APIエラー等）は何も投げずNoneを返す
    （呼び出し側はNoneを「AI判定なし、従来どおり通知する」として扱うこと）。"""
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
            # CloudflareのエッジがPythonの既定User-Agentをボットとしてブロックする
            # (error code: 1010)ため、通常のブラウザ風UAに差し替える
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
            ),
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

    return _parse_response(text)
