#!/usr/bin/env bash
# hit-linux-ids (SENTINEL) エージェント ネイティブインストーラー（macOS/launchd）
#
# Dockerを使わず、GitHub Releasesの単一バイナリをダウンロードして
# LaunchDaemon(root権限で常駐)として登録する。curl一発でも実行できる:
#
#   curl -fsSL https://raw.githubusercontent.com/hit1023/sentinel/main/install-macos.sh | sudo bash -s -- \
#     --webui-url http://192.168.0.18:8877 --token xxxxxxxx --host-label mac-mini
#
# 使い方:
#   ./install-macos.sh                対話形式でセットアップ
#   ./install-macos.sh --non-interactive \
#       --webui-url http://192.168.0.18:8877 \
#       --token xxxxxxxx \
#       --host-label mac-mini \
#       --version latest             非対話（CI/自動化向け）
set -euo pipefail

REPO="hit1023/sentinel"
INSTALL_DIR="/opt/sentinel"
CONFIG_DIR="/etc/sentinel"
DATA_DIR="/var/lib/sentinel"
LOG_DIR="/var/log/sentinel"
PLIST_PATH="/Library/LaunchDaemons/com.hit1023.sentinel-agent.plist"
LABEL="com.hit1023.sentinel-agent"

NON_INTERACTIVE=false
ARG_WEBUI_URL=""
ARG_TOKEN=""
ARG_HOST_LABEL=""
ARG_CF_TOKEN=""
ARG_WEB_LOG_PATHS=""
ARG_VERSION="latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --webui-url) ARG_WEBUI_URL="$2"; shift 2 ;;
    --token) ARG_TOKEN="$2"; shift 2 ;;
    --host-label) ARG_HOST_LABEL="$2"; shift 2 ;;
    --cf-ai-token) ARG_CF_TOKEN="$2"; shift 2 ;;
    --web-log-paths) ARG_WEB_LOG_PATHS="$2"; shift 2 ;;
    --version) ARG_VERSION="$2"; shift 2 ;;
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

if [ "$(id -u)" -ne 0 ]; then
  echo "エラー: root権限で実行してください（procnet_watch/integrity_watchが" >&2
  echo "        全プロセス・全ファイルシステムを見る必要があるため）。" >&2
  echo "        例: sudo ./install-macos.sh" >&2
  exit 1
fi

echo "=================================================="
echo " hit-linux-ids (SENTINEL) ネイティブインストーラー (macOS)"
echo "=================================================="
echo

# --- アーキテクチャ判定 ---
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) ASSET_ARCH="arm64" ;;
  x86_64) ASSET_ARCH="x86_64" ;;
  *)
    echo "エラー: 未対応のアーキテクチャです: $ARCH" >&2
    exit 1
    ;;
esac
ASSET_NAME="sentinel-agent-macos-${ASSET_ARCH}"

CURRENT_HOSTNAME="$(hostname -s 2>/dev/null || hostname)"

prompt() {
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

WEBUI_URL="$ARG_WEBUI_URL"
TOKEN="$ARG_TOKEN"
HOST_LABEL="$ARG_HOST_LABEL"
CF_TOKEN="$ARG_CF_TOKEN"
WEB_LOG_PATHS="$ARG_WEB_LOG_PATHS"
if [ -z "$WEB_LOG_PATHS" ] && [ -f "$CONFIG_DIR/env" ]; then
  WEB_LOG_PATHS="$(sed -n 's/^WEB_LOG_PATHS=//p' "$CONFIG_DIR/env" | tail -n 1)"
fi

[ -z "$WEBUI_URL" ] && prompt WEBUI_URL "司令塔WebUIのURL（例: http://192.168.0.18:8877）" ""
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

# --- GitHub Releasesからダウンロードするアセットのバージョン/URLを解決 ---
if [ "$ARG_VERSION" = "latest" ]; then
  RELEASE_API_URL="https://api.github.com/repos/${REPO}/releases/latest"
else
  RELEASE_API_URL="https://api.github.com/repos/${REPO}/releases/tags/${ARG_VERSION}"
fi

echo
echo "→ ${RELEASE_API_URL} からリリース情報を取得中..."
RELEASE_JSON="$(curl -fsSL "$RELEASE_API_URL")"
DOWNLOAD_URL="$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\": *\"[^\"]*${ASSET_NAME}\.tar\.gz\"" | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')"
RESOLVED_TAG="$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"

if [ -z "$DOWNLOAD_URL" ]; then
  echo "エラー: ${ASSET_NAME}.tar.gz がリリースアセットに見つかりませんでした。" >&2
  echo "        --version でタグを明示的に指定するか、リリースが公開されているか確認してください。" >&2
  exit 1
fi

echo "→ バージョン ${RESOLVED_TAG} をダウンロード中: $DOWNLOAD_URL"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/agent.tar.gz"
tar -xzf "$TMP_DIR/agent.tar.gz" -C "$TMP_DIR"

# --- 配置 ---
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
install -m 755 "$TMP_DIR/sentinel-agent" "$INSTALL_DIR/sentinel-agent"

# 未署名バイナリはGatekeeperの検疫属性(com.apple.quarantine)が付いていると
# 「開発元が未確認のため開けません」で弾かれるため、ダウンロード後に明示的に外す。
# コード署名+公証(notarization)は将来の課題として保留している。
xattr -d com.apple.quarantine "$INSTALL_DIR/sentinel-agent" 2>/dev/null || true

if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  cp "$TMP_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
  echo "✅ $CONFIG_DIR/config.yaml を新規作成しました（初回のみ、既存があれば上書きしません）"
else
  echo "→ 既存の $CONFIG_DIR/config.yaml を維持します（上書きしません）"
fi

{
  echo "CENTRAL_WEBUI_URL=$WEBUI_URL"
  echo "CENTRAL_INGEST_TOKEN=$TOKEN"
  echo "CENTRAL_HOST_LABEL=$HOST_LABEL"
  if [ -n "$CF_TOKEN" ]; then echo "CF_AI_GATEWAY_TOKEN=$CF_TOKEN"; fi
  if [ -n "$WEB_LOG_PATHS" ]; then echo "WEB_LOG_PATHS=$WEB_LOG_PATHS"; fi
} > "$CONFIG_DIR/env"
chmod 600 "$CONFIG_DIR/env"
echo "✅ $CONFIG_DIR/env を書き込みました"

cp "$TMP_DIR/com.hit1023.sentinel-agent.plist" "$PLIST_PATH"
chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# --- known_listen_ports のヒント表示（自動追記はしない、事故防止のため） ---
echo
echo "--- 参考: このホストの現在のリスニングポート ---"
if command -v lsof >/dev/null 2>&1; then
  lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1{print $9}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
  echo
else
  echo "(lsofが見つからないためスキップ)"
fi
echo "→ $CONFIG_DIR/config.yaml の procnet_watch.known_listen_ports /"
echo "  known_process_keywords をこのホストの構成に合わせて調整すると誤検知が減ります。"
echo

# --- 起動 (LaunchDaemon登録) ---
# 既に登録済みなら一度解除してから登録し直す（アップデート・再インストール対策）
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable "system/${LABEL}"

echo
echo "✅ セットアップ完了（バージョン ${RESOLVED_TAG}）。"
echo "   ログ確認: tail -f $LOG_DIR/agent.log"
echo "   数十秒後、司令塔WebUIの「HOSTS」パネルに '$HOST_LABEL' が表示されれば成功です。"
