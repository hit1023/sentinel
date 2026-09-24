# hit-linux-ids

学習・研究用の軽量ホスト型IDS（侵入検知）。Linuxサーバー（想定: gate, 192.168.0.18）上で
Dockerコンテナとして動作し、以下3種類の異常を検知してアラートを出す。

**注意**: 商用IDS（Wazuh/OSSEC/AIDE等）の代替ではなく、学習目的の自作ツール。
検知ロジックは単純なルールベースであり、誤検知・見逃しがあり得る。

## 検知内容

1. **認証ログ監視** (`app/auth_watch.py`)
   - SSHのログイン失敗を集計し、一定時間内に閾値を超えたらブルートフォースとして通知
   - 存在しないユーザーへのログイン試行を通知
   - ログイン成功も通知（設定でOFF可）
2. **ファイル整合性監視** (`app/integrity.py`)
   - `/etc`, `/root/.ssh`, `/etc/nginx`, `/etc/docker` 等の重要ファイルのSHA-256を記録
   - 初回はベースライン作成のみ。以降は追加/削除/改ざん（ハッシュ不一致）を検知
3. **プロセス・ネットワーク監視** (`app/procnet_watch.py`)
   - ホワイトリストに無い未知のプロセスが起動したら通知
   - 登録済みポート以外での新規LISTENを通知
   - 高CPU使用率のプロセスを通知

アラートは `data/alerts.log`（人間可読）と `data/alerts.jsonl`（構造化、WebUI用）に追記され、
`config.yaml` の `notify.webhook_url` を設定すればmailman/pushman等のWebhook API経由で
LINE/Web Push等にも転送できる。

## WebUI（サイバーパンク風リアルタイムダッシュボード）

`webui/` は上記アラートをブラウザでリアルタイム監視するためのダッシュボード。
FastAPI + WebSocketで `data/alerts.jsonl` の追記をtailし、ネオン配色・動くパーティクル
ネットワーク背景（`webui/static/netbg.js`）付きの画面に流し込む。

- 検知種別ごとの色分け（CRITICAL=赤、WARNING=amber、INFO=シアン/緑）
- 直近24時間の重大度別・カテゴリ別集計、ホストのプロセス数/リスニングポート数/CPU/メモリ表示
- `docker compose up -d --build` で `hit-linux-ids`（監視エージェント）と
  `hit-linux-ids-webui`（ダッシュボード、ポート8877）が同時に起動する
- アクセス: `http://<gateのIP>:8877/`（例: `http://192.168.0.18:8877/`）
- 外部公開する場合はgateのnginx-proxy-manager等でリバースプロキシ＋認証を挟むこと推奨
  （現状WebUI自体には認証機能なし。学習用途・LAN内利用が前提）

## セットアップ（gateでの実行を想定）

```bash
# gateへ配置
rsync -av /Volumes/USBSSD/docker/hit-linux-ids/ h-1:~/docker/hit-linux-ids/ --exclude data
# もしくは直接gate上でgit clone/rsync

ssh gate
cd ~/docker/hit-linux-ids
mkdir -p data
```

`app/config.yaml` を編集:
- `auth_watch.log_paths`: gateのディストロに合わせて調整（`/var/log/auth.log` が無ければ
  `use_journalctl: true` に切り替え、docker-compose.ymlの journal マウントを有効化）
- `notify.webhook_url` / `webhook_token`: 通知を飛ばす場合に設定（未設定ならログファイルのみ）
- `procnet_watch.known_listen_ports` / `known_process_keywords`: gateの実際の構成
  （technitium-dns, wg-easy, nginx-proxy-manager-jcom, portainer_agent 等）に合わせて調整

起動:

```bash
docker compose up -d --build
docker compose logs -f
```

## 動作の仕組み・制約

- `pid: host` + `network_mode: host` でホストのプロセス／ネットワーク名前空間を共有し、
  コンテナ内から `psutil` でホスト全体のプロセス・リスニングポートを見る設計。
- ファイル整合性監視はホストのルートを `/hostfs` として読み取り専用マウントして実現。
- 状態（ログ読み込み位置、整合性ベースライン、既知プロセスpid等）は `data/` 配下の
  JSONファイルに永続化される。コンテナを作り直しても `data/` を保持すれば継続する。
- あくまでルールベースの簡易検知。誤検知が出たら `config.yaml` のホワイトリスト・
  除外パターンを調整して運用する前提。

## 今後の拡張候補

- Fail2ban的な自動遮断（iptables/nftables操作）は未実装。検知のみで自動対処はしない設計
  （誤検知でgate自身のSSHが締め出されるリスクを避けるため）。
- Dockerコンテナ自体の異常（想定外イメージの起動等）を `docker.sock` 経由で監視する拡張。
