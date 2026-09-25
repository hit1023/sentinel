# hit-linux-ids（SENTINEL）

学習・研究用の軽量ホスト型IDS（侵入検知）。**マネージャー/エージェント構成**で、
複数のLinuxホストを1つのサイバーパンク風ダッシュボードから横断監視できる。
CRITICAL/WARNINGアラートは**Cloudflare AI Gateway経由でAIに脅威判定させ**、
非脅威と判定されたものは自動的に静音化する（AIに運用判断を任せる設計）。

> **このドキュメントについて**: 本プロジェクトはClaude(Sonnet 5)が実装を担当し、
> このセッション以降はCodexに引き継ぐ想定。設計判断の背景・既知の制約・
> 過去に踏んだ地雷を含めて詳しめに書いてあるので、まずここを一通り読んでから
> コードに手を入れることを推奨する。

**注意**: 商用IDS（Wazuh/OSSEC/AIDE等）の代替ではなく、学習目的の自作ツール。
検知ロジックは単純なルールベースであり、誤検知・見逃しがあり得る。実運用のセキュリティ
対策としては使わないこと（README末尾「今後の拡張候補」も参照）。

---

## 目次

1. [コンセプト・こだわった点](#コンセプトこだわった点)
2. [アーキテクチャ概要](#アーキテクチャ概要)
3. [ディレクトリ構成](#ディレクトリ構成)
4. [検知内容（エージェント）](#検知内容エージェント)
5. [AIトリアージ（Cloudflare AI Gateway）](#aiトリアージcloudflare-ai-gateway)
6. [WebUI（ダッシュボード）](#webuiダッシュボード)
7. [セットアップ・新規ホスト追加](#セットアップ新規ホスト追加)
8. [CI/CD](#cicd)
9. [現在デプロイ済みの環境](#現在デプロイ済みの環境)
10. [config.yaml リファレンス](#configyaml-リファレンス)
11. [既知の制約・ハマりどころ](#既知の制約ハマりどころ)
12. [これまでに踏んだバグと直し方（教訓）](#これまでに踏んだバグと直し方教訓)
13. [今後の拡張候補](#今後の拡張候補)

---

## コンセプト・こだわった点

このプロジェクトは「セキュリティ監視ツールとして完璧であること」よりも、
以下の2点を優先して作っている:

1. **機能よりサイバーなデザイン**: ネオン配色、動くパーティクルネットワーク背景、
   瞬きするアイ・アイコン、スキャンライン演出、CRITICAL検知時の画面フラッシュ、
   ターミナル風フィードなど、「見ていて気分が上がるダッシュボード」であることに
   実装時間の相当量を割いている。検知ロジック自体はシンプルなルールベースに留め、
   その分UIの演出を作り込む方針で進めた（`webui/static/`配下のCSS/JSがその蓄積）。
2. **AIに脅威判定を任せる**: Cloudflare AI Gateway（Workers AI）を使い、検知した
   異常が本当に脅威かどうかをLLMに判定させ、非脅威と判定されたものは自動的に
   目立たなくする（`ai_dismissed`）。ルールベース検知はどうしても誤検知（開発中の
   `sleep`コマンドやdockerの内部プロセス等）が多くなるが、それを人間がいちいち
   仕分けるのではなく「限りなくAIにお任せ」する運用思想。

## アーキテクチャ概要

```
┌─────────────┐   HTTP POST /api/ingest/alert    ┌──────────────────────┐
│  agent(gate) │ ───────────────────────────────▶ │                      │
├─────────────┤   HTTP POST /api/ingest/status    │  webui (通常gate1台)  │
│  agent(h-1) │ ───────────────────────────────▶ │  FastAPI + WebSocket │
├─────────────┤                                   │  alerts.jsonl        │
│ agent(mac)  │ ───────────────────────────────▶ │  hosts_status.json   │
└─────────────┘                                   └──────────┬───────────┘
                                                              │ WebSocket / REST
                                                              ▼
                                                     ブラウザ(ダッシュボード)

各agentは内部で Cloudflare AI Gateway (Workers AI) を叩いて
CRITICAL/WARNINGの脅威判定・日本語コメント生成も行う（agent→Cloudflare、webuiは関与しない）
```

- **エージェント**（`app/`）: 各監視対象ホストで動く。3種類のルールベース検知を行い、
  検知結果をCloudflare AI Gatewayでトリアージしたうえで、司令塔WebUIへHTTP POSTする。
  ローカルには人間可読ログ（`data/alerts.log`）と、各Watcherの状態ファイル
  （オフセット・ベースライン等）だけを持つ。**アラートの構造化データ(jsonl)は
  もうローカルには持たない**（司令塔WebUI側に一元化された）。
- **司令塔WebUI**（`webui/`）: 通常1台（gate）だけで動かす。全ホストからのPOSTを
  `data/alerts.jsonl`（アラート）と`data/hosts_status.json`（ホストごとの生存状況・
  CPU/MEM等）に集約し、ブラウザへREST + WebSocketで配信する。認証は共有Bearer
  トークン（`INGEST_TOKEN`環境変数）のみの簡易なもの。

## ディレクトリ構成

```
hit-linux-ids/
├── install.sh              # 新規ホスト導入インストーラー（後述）
├── docker-compose.yml       # agent(既定)/webui(--profile server)の2サービス定義
├── Dockerfile               # エージェント用イメージ
├── .env                     # ホスト固有の秘密値（gitignore対象、各ホストで手動作成）
├── .github/workflows/deploy.yml  # gate専用のCI/CD（後述）
│
├── app/                     # エージェント本体（Pythonイメージのビルド元）
│   ├── main.py               # エントリポイント。設定読み込み→監視ループ
│   ├── config.yaml            # 検知設定（全ホスト共通、gitで配布される）
│   ├── auth_watch.py           # 認証ログ監視
│   ├── integrity.py             # ファイル整合性監視（簡易AIDE）
│   ├── procnet_watch.py          # プロセス・ネットワーク異常検知
│   ├── notify.py                  # アラート発火の中枢（AIトリアージ呼び出し→
│   │                               中央WebUI送信→ローカルログ→Webhook、の順で処理）
│   ├── ai_triage.py                 # Cloudflare AI Gatewayへの問い合わせ・応答パース
│   ├── central_config.py             # ホスト固有設定(webui_url/token/host_label)の
│   │                                   解決ロジック（env var > config.yamlの順）
│   ├── status_writer.py               # CPU/MEM/プロセス数等のスナップショット組み立て
│   └── requirements.txt
│
└── webui/                    # 司令塔WebUI（別イメージ）
    ├── main.py                 # FastAPI本体。/api/ingest/*, /api/alerts, /api/stats,
    │                            # /api/hosts, /ws/alerts
    ├── Dockerfile
    ├── requirements.txt
    └── static/
        ├── index.html           # ダッシュボードのDOM構造
        ├── style.css             # ネオン配色・演出全般のCSS
        ├── app.js                 # フィード描画・フィルタ・WebSocket・チャート等
        └── netbg.js                # 背景の動くパーティクルネットワーク（canvas）
```

## 検知内容（エージェント）

1. **認証ログ監視**（`app/auth_watch.py`）
   - SSHのログイン失敗を集計し、`fail_window_seconds`秒間に`fail_threshold`回を
     超えたらブルートフォースとして通知（既定: 300秒に5回）
   - 存在しないユーザーへのログイン試行を通知
   - ログイン成功も通知（`notify_on_success`でOFF可）
   - **`sensitive_users`（root/admin等）への失敗ログインは、ブルートフォース閾値に
     達していなくても1回目から即座にWARNING通知する。**
     実在するユーザー名への失敗は「invalid user」判定にならないため、通常は
     `fail_threshold`回に達するまで完全に無音になってしまう（＝存在しないユーザー名
     [例: admin@]への攻撃はすぐ警告されるのに、より危険なroot単体への数回の
     失敗試行は見逃されるという逆転現象があった。これに気づいて追加した挙動）
   - **初回起動時は既存の`auth.log`を遡って読まず、ファイル末尾から監視を開始する**
     （でないと巨大な既存ログを一括処理して大量の過去ログイン通知が出る。実際に
     この不具合を踏んで直した経緯あり→「教訓」節参照）
2. **ファイル整合性監視**（`app/integrity.py`、簡易AIDE）
   - `/etc`, `/root/.ssh`, `/etc/nginx`, `/etc/docker` 等の重要ファイルのSHA-256を記録
   - 初回はベースライン作成のみ。以降は追加/削除/改ざん（ハッシュ不一致）を検知
3. **プロセス・ネットワーク監視**（`app/procnet_watch.py`）
   - `known_process_keywords`に無い未知のプロセスが起動したら通知（部分一致判定）
   - `known_listen_ports`以外での新規LISTENを通知
   - 高CPU使用率のプロセスを通知（`cpu_alert_percent`、既定90%）
   - **CPU%計測には要注意の実装ノートあり**（後述「教訓」節）

いずれも`Notifier.alert(category, message, severity)`を呼ぶだけの単純なインターフェースで、
新しい検知器を追加する場合はこのメソッドを呼ぶWatcherクラスを1つ書いて`app/main.py`の
`watchers`リストに足せばよい。

## AIトリアージ（Cloudflare AI Gateway）

CRITICAL/WARNINGアラート発生時、`app/notify.py`の`Notifier.alert()`が
`app/ai_triage.py`の`triage()`を呼び出し、生ログをWorkers AI（Cloudflare AI Gateway
経由）に渡して以下を行わせる:

1. **�eneral脅威判定**（`THREAT: YES` / `THREAT: NO`）
2. **日本語1〜2文のトリアージコメント**（何が起きたか・緊急度・次に確認すべきこと）

プロンプト（`ai_triage.py`の`SYSTEM_PROMPT`）は、応答を必ず
```
THREAT: YES または THREAT: NO
（続けてコメント本文）
```
の2行形式に固定させ、`_parse_response()`でパースする。**想定外の形式が返ってきた場合は
安全側（`is_threat=True`、つまり通知は消さない）に倒すフェイルセーフ**になっている。

`auto_dismiss_non_threats: true`（既定）の場合、`THREAT: NO`と判定されたアラートは
`Notifier.alert()`内で重大度が`info`に格下げされ、`ai_dismissed: true` /
`original_severity: <元の重大度>` が記録に付与される。格下げされたものは:
- WebUIの統計（CRITICAL/WARNING件数）には計上されない
- CRITICALフラッシュ演出・Webhook通知の対象外になる
- **削除はされず**、フィード内には半透明+「AI SILENCED」バッジ付きで表示され続ける
  （後から見返して監査できる）
- **TOPの「AI LATEST VERDICT」バナーには出さない**（目立たせる必要がないため。
  これはユーザーからのフィードバックで後から直した挙動）

### ユーザー起点の抑制ルール（AIとは独立した誤検知除外）

AIの判定に頼らず、**人間が「これは脅威ではない」と一度教えたものは確実に黙らせたい**
というケース（開発用コマンド、既知の運用ファイルなど）向けに、AIトリアージとは別の
抑制ルール機能をWebUI側に持たせている。

- フィード上のCRITICAL/WARNINGアラートにマウスオーバーすると「✕ 誤検知」ボタンが出る
- クリックすると、カテゴリ＋メッセージに含まれる文字列（部分一致）＋対象ホスト
  （そのホストのみ／全ホスト共通を選択）でルールを登録できる
- 登録後は`/api/ingest/alert`の受信時点で**AIの判定より先に**このルールを適用し、
  一致したアラートは強制的にINFOへ格下げする（`suppressed: true`、`original_severity`は
  保持するので監査ログからは追える）
- サイドパネルの「SUPPRESSION RULES」で登録済みルールの一覧・削除ができる
- **ルール登録は将来のingestにしか効かない**（`/api/ingest/alert`受信時にその場で
  評価するだけなので、登録前に既にjsonlへ書き込み済みの過去アラートは対象外）。
  過去分にも遡って適用したい場合は「既存にも適用」ボタン
  （`POST /api/suppressions/reapply`）で、現在登録中の全ルールを`alerts.jsonl`の
  既存レコードに再評価・書き戻しできる
- 実装は`webui/main.py`の`_apply_suppressions()`。**WebUI側だけで完結する**ため、
  エージェント側の再デプロイは不要（AIトリアージ自体は引き続きagent側で実行されるので
  Cloudflareへの呼び出し自体は減らない点に注意。呼び出し自体を減らしたい場合は
  `config.yaml`の`known_process_keywords`等の恒久的なホワイトリストで対応する）

### セットアップ手順

1. Cloudflareダッシュボード → AI → **AI Gateway** で新規Gatewayを作成
   （現在の値: gateway名 `sentinel`、認証はOFFにしてある。理由は下記「制約」参照）
2. **My Profile → API Tokens** で「Workers AI」テンプレートのトークンを発行
   （`Account.Workers AI:Read` + `Edit`）
3. 各ホストの`.env`に以下を設定:
   ```
   CF_AI_GATEWAY_TOKEN=<発行したトークン>
   ```
4. `app/config.yaml`の`ai_triage`セクションで`enabled: true`、
   `cloudflare_account_id` / `cloudflare_gateway_id`を設定（既に設定済み、非秘密情報
   なのでgit管理下に置いている）
5. `docker compose up -d --build`

### 設計上の注意点

- **モデル**: 既定で軽量・高速な`@cf/meta/llama-3.1-8b-instruct-fast`を使用。
  精度を上げたい場合は`ai_triage.model`を別のWorkers AIモデルに変更する。
- **トリアージ対象の絞り込み**: `ai_triage.trigger_severities`（既定: critical, warning）
  でINFO等の高頻度アラートは呼ばない（コスト・レイテンシ抑制）。procnet_watchの
  初回スキャン等は大量の"未知プロセス"警告を出すため、これを絞らないとAI Gateway
  へのリクエストが大量発生する点に注意。
- **失敗時の挙動**: タイムアウト（既定8秒）・APIエラー時は`triage()`が`None`を返し、
  `Notifier.alert()`は通知自体を止めない（`ai_summary`が`None`のまま記録される）。
- **User-Agent偽装が必須**: CloudflareエッジがPython標準ライブラリ`urllib`の既定
  User-Agentをボットとして`HTTP 403 (error code: 1010)`でブロックするため、
  `ai_triage.py`内でブラウザ風のUser-Agentヘッダーを明示的に付けている
  （これも実際にハマって直した箇所。ここを消すと突然AIトリアージが全滅するので注意）。

## WebUI（ダッシュボード）

サイバーパンク風の演出:

- 動くパーティクルネットワーク背景（`netbg.js`、canvas自作、外部ライブラリ不使用）
- 瞬きする目のロゴ（SVG、`eye-blink-group`を上下に潰す/戻すアニメーションで
  「まぶたを重ねて隠す」のではなく「実際に目が閉じる」ように見せている）
- 上から下へ流れる細いスキャンライン（s-quad.com風、`.scan-sweep`）
- ターミナル風のライブフィード（macOS風3色ドット、`> _`点滅カーソル）
- CRITICAL検知時の画面全体フラッシュ + 該当統計カードの光るアニメーション
- 各統計値のリアルタイムスパークライン（棒グラフ、canvas自作）とCPU波形チャート
  （ベジェ曲線、全ホスト平均）

機能面:

- **マルチホスト表示**: フィード各行にホストバッジ、「HOSTS」パネルに全ホストの
  オンライン/オフライン・CPU/MEM・**ホストごとのCPU/MEM推移ミニスパークライン**、
  ヘッダーに「オンライン数/全ホスト数」バッジ。全ホスト平均の波形チャートは
  「個々のホストの傾向が分からずスペースの無駄」というフィードバックで廃止し、
  ホスト別のミニグラフに一本化した
- **統計カードクリックでフィルタ**: CRITICAL/WARNING/INFOカードクリックでその重大度
  だけに、PROCESSES/LISTEN PORTSカードクリックで`procnet_watch`カテゴリだけに
  フィードを絞り込む。TOTAL ALERTSカードで解除。同じカード再クリック、または
  フィード上部の「FILTER: ◯◯ ✕」チップでもトグル解除できる
  （実装: `app.js`の`allAlerts`配列に生データを保持し、`activeFilter`に応じて
  再描画する方式。WebSocketで届く新規アラートもフィルタ条件に合わないものは
  DOM追加をスキップする）
- **AI LATEST VERDICTバナー**: 最新のAIトリアージ結果（非脅威判定を除く）をヘッダー
  直下に常時表示
- 認証機能は**現状なし**。LAN内利用が前提。外部公開する場合は
  nginx-proxy-manager等でリバースプロキシ＋認証を挟むこと。

### バックエンドAPI（`webui/main.py`）

| エンドポイント | 用途 |
|---|---|
| `POST /api/ingest/alert` | エージェントからのアラート受信（`Authorization: Bearer <INGEST_TOKEN>`） |
| `POST /api/ingest/status` | エージェントからの状態スナップショット受信 |
| `GET /api/alerts?limit=&host=` | 直近アラート取得（ホスト絞り込み可） |
| `GET /api/stats` | 24時間集計・全ホストの状態・カテゴリ内訳 |
| `GET /api/hosts` | ホスト一覧とオンライン判定（`HOST_STALE_SECONDS`、既定300秒） |
| `GET /api/alerts/history?severity=&host=&since_epoch=&limit=` | **長期監査用**。CRITICAL/WARNING（元severity基準、AI格下げ後も含む）だけをSQLiteから検索 |
| `WS /ws/alerts` | `alerts.jsonl`の追記をtailしてリアルタイム配信 |

### データ永続化の設計（2層構成）

- **`data/alerts.jsonl`**: 全重大度（info含む）の生ログ。追記オンリー、直近tail表示・
  WebSocket配信用。`/api/stats`等は末尾5000行だけ読むため、長期間ではINFOの多さに
  埋もれて古いCRITICALが実質検索不能になる。
- **`data/alerts_important.db`（SQLite）**: **元severityがcritical/warningだったものだけ**
  を`id`をキーに永続保存（AIが非脅威判定して`info`に格下げしたものも`original_severity`で
  拾って残す）。ホスト・重大度・期間で検索できる`/api/alerts/history`から利用する。
  INFOを含めなかったのは、頻度が高く監査価値も低いため、SQLite化の恩恵よりファイル肥大化の
  デメリットが上回ると判断したため。将来INFOも保存したくなった場合は
  `webui/main.py`の`PERSIST_SEVERITIES`に`"info"`を足すだけでよい。

## セットアップ・新規ホスト追加

### `install.sh`（推奨）

```bash
git clone git@github.com:hit1023/sentinel.git hit-linux-ids
cd hit-linux-ids
./install.sh                  # 対話形式（エージェントのみ）
./install.sh --server          # 司令塔WebUIも同居させる場合（通常はgateだけ）
```

対話で聞かれる項目: 司令塔WebUIのURL、共有Ingestトークン、ホスト表示名、
（任意で）Cloudflare AI Gatewayトークン。`.env`の作成→そのホストの現在の
リスニングポート一覧の表示（`config.yaml`調整の参考用）→`docker compose up -d --build`
まで自動で行う。

非対話（自動化向け）:
```bash
./install.sh --non-interactive \
  --webui-url http://192.168.0.18:8877 \
  --token <共有トークン> \
  --host-label h-1
```

### 手動セットアップ

`install.sh`を使わない場合、`.env`を手動で用意して`docker compose up -d --build`
（司令塔ホストなら`--profile server`を追加）するだけでよい。`.env`の内容は
[config.yamlリファレンス](#configyaml-リファレンス)を参照。

### 新規ホストのチェックリスト

1. リポジトリをclone（読み取り専用deploy key推奨。gateには`sentinel-ai-triage`用とは
   別に、GitHubリポジトリ自体のread-only deploy keyを`~/.ssh/id_ed25519_sentinel`に
   設置し、`~/.ssh/config`に`github.com-sentinel`エイリアスを作ってある。他ホストへ
   展開する場合も同様の専用deploy key方式を推奨）
2. `.env`を作成（`install.sh`推奨）
3. `app/config.yaml`の`procnet_watch.known_listen_ports` / `known_process_keywords`を
   そのホストの実構成に合わせて調整（`ss -tlnp` / `docker ps`で確認）
4. **重要**: このホストがCI/CD対象外（gate以外）の場合、`config.yaml`をホスト固有に
   編集したら`git update-index --skip-worktree app/config.yaml`しておくこと。
   でないと次回`git pull`時にマージ処理が走り、意図せず衝突・上書きの可能性がある
   （gateは`git reset --hard`で強制上書きするCI方式なので、そもそも
   ホスト固有の値は`config.yaml`に書かず`.env`に書く設計にしてある。詳細は
   `app/config.yaml`冒頭のコメントおよび下記「既知の制約」参照）
5. `docker compose up -d --build`
6. 司令塔WebUIの「HOSTS」パネルに新しいホストが緑ドットで現れれば成功

## CI/CD

**gateのみ**自動デプロイ対象。`main`ブランチへのpushで、gate上の自己ホスト
GitHub Actionsランナー（ラベル: `sentinel`、他プロジェクトのDrift/i-was-hereと
同じ方式）が以下を実行する（`.github/workflows/deploy.yml`）:

```
git fetch origin main && git reset --hard origin/main
docker compose --profile server up -d --build
curl -sf http://localhost:8877/api/stats  # ヘルスチェック
```

h-1・Mac mini等のエージェント専用ホストは対象外。コード更新は手動で
`git pull && docker compose up -d --build`（h-1のように`config.yaml`を
skip-worktreeにしている場合は`git pull`が安全）。

### gateの初期セットアップ済み事項

- `~/docker/hit-linux-ids`をgit cloneで配置（`~/.ssh/id_ed25519_sentinel`という
  専用read-only deploy key経由、`~/.ssh/config`に`github.com-sentinel`エイリアス）
- `~/actions-runner-sentinel/`にGitHub Actions self-hosted runnerをsystemdサービス
  として常駐（`actions.runner.hit1023-sentinel.gate-sentinel.service`）
- ランナーの登録トークンは`gh api -X POST repos/hit1023/sentinel/actions/runners/registration-token`
  で発行したもの（有効期限があるため、再セットアップが必要な場合は再発行すること）

## 現在デプロイ済みの環境

| ホスト | 役割 | 備考 |
|---|---|---|
| gate (192.168.0.18) | 司令塔WebUI + エージェント | CI/CD対象。ポート8877で公開 |
| h-1 (192.168.0.20) | エージェントのみ | `config.yaml`をskip-worktree化済み |
| Mac mini | エージェントのみ | Docker Desktopの制約あり（下記参照） |

3ホスト共通のCloudflareリソース:
- AI Gateway: account_id `a02903a62c568fcf8fd62fc7bef36aa0` / gateway `sentinel`
- Workers AI用トークン: `sentinel-ai-triage`という名前で発行済み（各ホストの
  `.env`の`CF_AI_GATEWAY_TOKEN`にコピー配布済み）

共有Ingestトークンは3ホストの`.env`の`CENTRAL_INGEST_TOKEN`にコピー配布済み
（値そのものはこのMarkdownには書かない。各ホストの`.env`を参照）。

## config.yaml リファレンス

`app/config.yaml`はgit管理下で全ホスト共通デプロイされる。**ホストごとに異なるべき
値（`central.*`のURL/トークン/ホスト名、Cloudflareトークン）は`.env`（gitignore対象）
で上書きする設計**（`app/central_config.py`が環境変数優先で解決する）。

| キー | 既定値 | 説明 |
|---|---|---|
| `interval_seconds` | 60 | 監視ループの間隔（秒） |
| `central.enabled` | true | 中央WebUIへの送信を有効化するか |
| `central.webui_url` | "" | **.envの`CENTRAL_WEBUI_URL`推奨**。司令塔のURL |
| `central.ingest_token` | "" | **.envの`CENTRAL_INGEST_TOKEN`推奨** |
| `central.host_label` | "" | **.envの`CENTRAL_HOST_LABEL`推奨**。空ならOSホスト名 |
| `auth_watch.fail_threshold` | 5 | ブルートフォース判定の失敗回数閾値 |
| `auth_watch.fail_window_seconds` | 300 | 上記の時間窓 |
| `auth_watch.notify_on_success` | true | ログイン成功も通知するか |
| `auth_watch.use_journalctl` | false | trueならjournalctl方式（journalマウントも要有効化） |
| `auth_watch.sensitive_users` | root, admin, administrator, ubuntu | これらのユーザーへの失敗ログインは閾値未満でも即WARNING |
| `integrity_watch.watch_paths` | `/etc`, `/root/.ssh`等 | 整合性監視対象（コンテナ内は`/hostfs`配下） |
| `procnet_watch.known_listen_ports` | （ホストごとに要調整） | 既知ポート一覧 |
| `procnet_watch.known_process_keywords` | （ホストごとに要調整） | 既知プロセス名（部分一致） |
| `procnet_watch.cpu_alert_percent` | 90 | 高CPU通知の閾値(%) |
| `notify.webhook_url` / `webhook_token` | "" | mailman/pushman等への転送用（任意） |
| `ai_triage.enabled` | true | AIトリアージを使うか |
| `ai_triage.trigger_severities` | critical, warning | トリアージ対象の重大度 |
| `ai_triage.cloudflare_account_id` / `cloudflare_gateway_id` | 設定済み | 非秘密情報 |
| `ai_triage.model` | `@cf/meta/llama-3.1-8b-instruct-fast` | Workers AIモデル名 |
| `ai_triage.api_token` | "" | **.envの`CF_AI_GATEWAY_TOKEN`推奨** |
| `ai_triage.timeout_seconds` | 8 | Gateway呼び出しのタイムアウト |
| `ai_triage.auto_dismiss_non_threats` | true | 非脅威判定を自動でINFOへ格下げするか |

## 既知の制約・ハマりどころ

- **Mac(Docker Desktop)での`network_mode: host`**: 実際のmacOSホストではなく、
  Docker Desktopが内部で使うLinux VMを見ることになる。Mac miniを「エージェントの
  1台」として動かしても、見えるのはあくまでVM内部の状態（学習・動作確認用途と
  割り切って使う）。また、同じ理由でVM内`localhost`は「そのホスト自身」を指さない
  ため、Mac上でagentとwebuiを同居させても`localhost:8877`には到達できない
  （外部LAN IPへの接続は問題ない）。
- **WebUIに認証機能なし**: LAN内利用が前提。外部公開するならリバースプロキシで
  認証を挟むこと。
- **AI Gatewayの認証はOFF**: Gateway作成時に「認証済みゲートウェイ」をOFFにしている
  （ONのままだと`cf-aig-authorization`ヘッダーが別途必要になり実装が複雑化するため）。
  Workers AI呼び出し自体は`CF_AI_GATEWAY_TOKEN`（Cloudflare APIトークン）で保護されて
  いるので、Gateway側の追加認証がなくても第三者が勝手に推論を実行することはできない
  （はず。要再確認）。
- **AIトリアージのコスト**: procnet_watchの初回スキャンや大量の未知プロセス検知時、
  トリアージ対象（critical/warning）が多いとWorkers AIへのリクエストが急増する。
  現状レート制限やコスト上限の仕組みは未実装。

## これまでに踏んだバグと直し方（教訓）

実装中に実際に発生し、修正したバグ。同種の問題を作り込まないための参考に:

1. **auth_watch初回起動時のログ全読み込み** — 51MBの既存`auth.log`を最初から
   読んでしまい、過去の全ログイン成功(約6万件)を通知してしまった。
   → 初回はファイル末尾から監視開始するよう修正（`_iter_new_lines_from_file`）。
2. **procnet_watchのCPU%が数千%になる誤検知** — `psutil.process_iter()`の
   attrsに`"cpu_percent"`を含めると、その場での内部計測と直後の
   `p.cpu_percent(interval=None)`呼び出しがほぼ無時間差の二重計測になり、
   OSのクロック粒度の丸め誤差で`17577.8%`のような荒唐無稽な値が出た。
   → attrsから`cpu_percent`を除去し1回だけ計測。念のためCPUコア数×100%を
   超える値は無視するガードも追加。
   （副次的な発見: AIがこの壊れた数字`17577.8%`を要約する際、桁を見誤って
   `175.78%`と書いてしまう事例も確認。生データが壊れているとAIの要約も
   信頼できない、という実例）
3. **Cloudflare AI GatewayがHTTP 403 (error code: 1010)で全滅** — Python
   `urllib`の既定User-Agentがボットとしてブロックされていた。
   → ブラウザ風User-Agentを明示的に設定（`ai_triage.py`）。
4. **Mac Docker Desktopの`network_mode: host`が実ホストを共有しない** —
   ローカルテスト時、コンテナ内`localhost`から同ホストのWebUIに到達できず
   `Connection refused`。実Linuxホスト(gate)では問題なし。上記「既知の制約」参照。
5. **`.env`の反映漏れ** — gateへ`central`関連の環境変数を追記した直後にCIが
   `docker compose up`済みだったため、コンテナが古い`.env`のまま起動していた。
   → `.env`変更後は`docker compose up -d --force-recreate`が必要な場合がある
   （docker composeは`.env`を`up`実行時にしか読まない）。

## 今後の拡張候補

- Fail2ban的な自動遮断（iptables/nftables操作）は未実装。検知のみで自動対処は
  しない設計（誤検知でホスト自身のSSHが締め出されるリスクを避けるため）。
- Dockerコンテナ自体の異常（想定外イメージの起動等）を`docker.sock`経由で
  監視する拡張。
- AIトリアージのレート制限・コスト上限（Workers AI呼び出し回数が青天井）。
- h-1・Mac mini等のエージェント専用ホストもCI/CD対象にする（自己ホストランナーの
  追加、またはgateからのSSHデプロイ等）。
- WebUIへの認証機能追加（現状LAN内・信頼境界内での利用が前提）。
- ホストがオフラインになったこと自体をアラートとして扱う（現状は「HOSTS」パネルの
  表示が変わるだけで、通知としては発火しない）。
