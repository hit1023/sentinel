#!/usr/bin/env bash
# hit-linux-ids (SENTINEL) エージェント インストーラー
#
# 新しいホストにエージェントを展開するときの定型作業
# （.envの作成、known_listen_portsのヒント表示、docker composeの起動）
# をまとめたスクリプト。リポジトリをclone済みのディレクトリ内で実行する。
#
# 使い方:
#   ./install.sh                 対話形式でセットアップ（エージェントのみ）
#   ./install.sh --server        司令塔WebUIも同居させる場合（通常はgateだけ）
#   ./install.sh --non-interactive \
#       --webui-url http://192.168.0.18:8877 \
#       --token xxxxxxxx \
#       --host-label h-1         非対話（CI/自動化向け）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SERVER_MODE=false
NON_INTERACTIVE=false
ARG_WEBUI_URL=""
ARG_TOKEN=""
ARG_HOST_LABEL=""
ARG_CF_TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_MODE=true; shift ;;
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --webui-url) ARG_WEBUI_URL="$2"; shift 2 ;;
    --token) ARG_TOKEN="$2"; shift 2 ;;
    --host-label) ARG_HOST_LABEL="$2"; shift 2 ;;
    --cf-ai-token) ARG_CF_TOKEN="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "不明なオプション: $1" >&2
      exit 1
      ;;
  esac
done

echo "=================================================="
echo " hit-linux-ids (SENTINEL) エージェント インストーラー"
echo "=================================================="
echo

# --- 前提チェック ---
if ! command -v docker >/dev/null 2>&1; then
  echo "エラー: dockerコマンドが見つかりません。先にDockerをインストールしてください。" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "エラー: docker compose (v2) が見つかりません。" >&2
  exit 1
fi

CURRENT_HOSTNAME="$(hostname -s 2>/dev/null || hostname)"

prompt() {
  # prompt <変数名> <質問文> <デフォルト値>
  local __varname="$1" __question="$2" __default="$3" __input
  if [ "$NON_INTERACTIVE" = true ]; then
    return
  fi
  if [ -n "$__default" ]; then
    read -r -p "$__question [$__default]: " __input
  else
    read -r -p "$__question: " __input
  fi
  printf -v "$__varname" '%s' "${__input:-$__default}"
}

# --- .env の作成（既存があれば内容を引き継ぎつつ上書き確認） ---
if [ -f .env ]; then
  echo "既存の .env が見つかりました。上書きする項目だけ更新します。"
fi

WEBUI_URL="$ARG_WEBUI_URL"
TOKEN="$ARG_TOKEN"
HOST_LABEL="$ARG_HOST_LABEL"
CF_TOKEN="$ARG_CF_TOKEN"

if [ "$SERVER_MODE" = true ]; then
  echo "→ 司令塔モード（このホスト自身がWebUIも兼ねる）"
  [ -z "$WEBUI_URL" ] && prompt WEBUI_URL "司令塔WebUIのURL（このホスト自身なので通常はlocalhost）" "http://localhost:8877"
else
  echo "→ エージェント専用モード（司令塔WebUIは別ホストで稼働）"
  [ -z "$WEBUI_URL" ] && prompt WEBUI_URL "司令塔WebUIのURL（例: http://192.168.0.18:8877）" ""
fi

[ -z "$TOKEN" ] && prompt TOKEN "共有Ingestトークン（司令塔側のCENTRAL_INGEST_TOKENと同じ値）" ""
[ -z "$HOST_LABEL" ] && prompt HOST_LABEL "このホストの表示名" "$CURRENT_HOSTNAME"

if [ "$NON_INTERACTIVE" = false ]; then
  echo
  read -r -p "AIトリアージ(Cloudflare AI Gateway)用のトークンを設定しますか？ [y/N]: " USE_AI
  if [[ "$USE_AI" =~ ^[Yy]$ ]]; then
    prompt CF_TOKEN "Workers AI権限のCloudflare APIトークン" ""
  fi
fi

if [ -z "$WEBUI_URL" ]; then
  echo "エラー: 司令塔WebUIのURLは必須です。" >&2
  exit 1
fi

{
  echo "CENTRAL_WEBUI_URL=$WEBUI_URL"
  echo "CENTRAL_INGEST_TOKEN=$TOKEN"
  echo "CENTRAL_HOST_LABEL=$HOST_LABEL"
  [ -n "$CF_TOKEN" ] && echo "CF_AI_GATEWAY_TOKEN=$CF_TOKEN"
} > .env
chmod 600 .env
echo "✅ .env を書き込みました（このファイルはgit管理外です）"

mkdir -p data

# --- known_listen_ports のヒント表示（自動追記はしない、事故防止のため） ---
echo
echo "--- 参考: このホストの現在のリスニングポート ---"
if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
  echo
elif command -v netstat >/dev/null 2>&1; then
  netstat -tlnp 2>/dev/null | awk 'NR>2{print $4}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
  echo
else
  echo "(ss/netstatが見つからないためスキップ)"
fi
echo "→ app/config.yaml の procnet_watch.known_listen_ports /"
echo "  known_process_keywords をこのホストの構成に合わせて調整すると誤検知が減ります。"
echo

# --- 起動 ---
COMPOSE_ARGS=(up -d --build)
if [ "$SERVER_MODE" = true ]; then
  COMPOSE_ARGS=(--profile server "${COMPOSE_ARGS[@]}")
fi

echo "docker compose ${COMPOSE_ARGS[*]} を実行します..."
docker compose "${COMPOSE_ARGS[@]}"

echo
echo "✅ セットアップ完了。"
echo "   ログ確認: docker compose logs -f hit-linux-ids"
if [ "$SERVER_MODE" = true ]; then
  echo "   ダッシュボード: http://localhost:8877/"
else
  echo "   数十秒後、司令塔WebUIの「HOSTS」パネルに '$HOST_LABEL' が表示されれば成功です。"
fi
