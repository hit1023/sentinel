#!/bin/bash
# gate で一度だけ実行する（sudo が必要）: SENTINEL の「自動ブロック」を fail2ban につなぐ。
#   ssh gate
#   cd ~/docker/hit-linux-ids && git pull && sudo bash tools/setup-fail2ban-sentinel.sh
#
# 仕組み: SENTINEL(WebUIコンテナ)が、ブロックすると決めたIPを「SENTINEL-BAN <IP> ...」という行として
#   <data>/sentinel_blocklist.log に追記する。fail2ban の専用jail(sentinel-abuse)がこのファイルを監視し、
#   追記された行のIPを iptables で24時間ブロックする（ブロックの判断は SENTINEL 側。fail2ban側は maxretry=1）。
# 元に戻すには:
#   sudo rm /etc/fail2ban/jail.d/sentinel-abuse.local /etc/fail2ban/filter.d/sentinel-abuse.conf && sudo fail2ban-client reload
set -euo pipefail
DATA_DIR="${SENTINEL_DATA_DIR:-/home/hit/docker/hit-linux-ids/data}"
HOME_IP="${SENTINEL_HOME_IP:-106.179.13.173}"   # 自宅の回線のグローバルIP（自分を締め出さないための除外）

cat > /etc/fail2ban/filter.d/sentinel-abuse.conf <<CONF
# SENTINEL(WebUI)が書き出す「SENTINEL-BAN <IP> ...」の行を拾う
[Definition]
# fail2banは、行頭の日時を認識すると、その部分を取り除いてから照合する。日時が取れた場合も取れない場合も合うよう、行頭を固定しない
failregex = SENTINEL-BAN <HOST>\b
ignoreregex =
CONF

cat > /etc/fail2ban/jail.d/sentinel-abuse.local <<CONF
[sentinel-abuse]
enabled  = true
filter   = sentinel-abuse
logpath  = ${DATA_DIR}/sentinel_blocklist.log
backend  = auto
maxretry = 1
findtime = 86400
bantime  = 86400
port     = ssh
# 自分を締め出さない（ループバック・LAN・自宅の回線）
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ${HOME_IP}
CONF

touch "${DATA_DIR}/sentinel_blocklist.log"
chmod 644 "${DATA_DIR}/sentinel_blocklist.log"

echo "--- 設定の検査 ---"
echo "2026-10-12T09:00:00+0900 SENTINEL-BAN 203.0.113.9 score=100 events=7" > /tmp/sentinel-ban-sample.log
fail2ban-regex /tmp/sentinel-ban-sample.log /etc/fail2ban/filter.d/sentinel-abuse.conf | grep -E "Lines|Date" || true
rm -f /tmp/sentinel-ban-sample.log
fail2ban-client -t
echo "--- 反映 ---"
fail2ban-client reload
fail2ban-client status sentinel-abuse
echo "完了。SENTINELの画面（⚙設定 → 🚨通報）で、自動ブロックのモードを「オン」にすると実際にブロックが始まります。"
