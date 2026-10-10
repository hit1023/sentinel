# config.yaml リファレンス

`app/config.yaml`はgit管理下で全ホスト共通デプロイされる。**ホストごとに異なるべき
値（`central.*`のURL/トークン/ホスト名、Cloudflareトークン）は`.env`（gitignore対象）
で上書きする設計**（`app/central_config.py`が環境変数優先で解決する）。

| キー | 既定値 | 説明 |
|---|---|---|
| `interval_seconds` | 60 | 監視ループの間隔（秒） |
| `central.enabled` | true | マネージャーへの送信を有効化するか |
| `central.webui_url` | "" | **.envの`CENTRAL_WEBUI_URL`推奨**。マネージャーのURL |
| `central.ingest_token` | "" | **.envの`CENTRAL_INGEST_TOKEN`推奨** |
| `central.host_label` | "" | **.envの`CENTRAL_HOST_LABEL`推奨**。空ならOSホスト名 |
| `auth_watch.fail_threshold` | 5 | ブルートフォース判定の失敗回数閾値 |
| `auth_watch.fail_window_seconds` | 300 | 上記の時間窓 |
| `auth_watch.notify_on_success` | true | ログイン成功も通知するか |
| `auth_watch.use_journalctl` | false | trueならjournalctl方式（journalマウントも要有効化） |
| `auth_watch.sensitive_users` | root, admin, administrator, ubuntu | これらのユーザーへの失敗ログインは閾値未満でも即WARNING |
| `auth_watch.geoip_enabled` | true | GeoIP+逆引き+見慣れない国からのログイン検知を有効化 |
| `auth_watch.compromise_detection` | true | 失敗連発後の同一IPからのログイン成功を侵入成功の疑いとしてCRITICAL通知する |
| `auth_watch.compromise_window_seconds` | 3600 | 上記で失敗を数える時間窓（秒） |
| `auth_watch.compromise_min_failures` | 5 | 上記の失敗回数の閾値 |
| `package_watch.enabled` | true | 脆弱性照合用にdpkgのパッケージ一覧をマネージャーへ送る（Ubuntu/Debianのみ） |
| `package_watch.resend_hours` | 24 | 構成に変化が無くても一覧を再送する間隔（時間） |
| `auth_watch.privilege_events` | true | 新規ユーザー作成・特権グループ追加(CRITICAL)、su・sudo失敗・パスワード変更(WARNING)を通知（auth.logのファイル方式のみ） |
| `secret_watch.enabled` / 環境変数`SECRET_WATCH_ROOTS` | false / "" | 秘密情報の混入検知。環境変数にリポジトリの場所（カンマ区切り）を設定すると有効化される |
| `secret_watch.scan_roots` | [] | 走査するgitリポジトリ（そのもの、または直下にリポジトリを持つディレクトリ） |
| `secret_watch.interval_hours` / `history_interval_hours` | 24 / 168 | 走査間隔 / git履歴まで含めた走査の間隔（時間） |
| `secret_watch.check_permissions` | true | `.env`・秘密鍵が他のユーザーから読める権限でないかも見る |
| `web_watch.enabled` / `WEB_LOG_PATHS` | false / "" | Webログ監視。Docker版はホストごとの`.env`で`WEB_LOG_PATHS`を指定すると有効化 |
| `web_watch.window_seconds` / `scan_distinct_paths` / `auth_failures` / `not_found_distinct_paths` | 300 / 5 / 10 / 30 | Web探索・認証失敗・404探索の判定閾値 |
| `web_watch.script_probe_paths` | 4 | スクリプト(.php/.jsp等)を異なるパスで要求した数がこれ以上でWARNING |
| `web_watch.ignore_private_ips` | true | LAN内クライアントを、ペイロード/スキャナ/スクリプト探索/成功応答の検知から除外 |
| `web_watch.success_critical` | true | 機密パス・スクリプトのパスへの2xx応答（404を返すサイトのみ）をCRITICAL通知 |
| `web_watch.script_hosts` | [] | 正規にスクリプトを配信するホスト名（スクリプト探索・成功応答から除外） |
| `integrity_watch.watch_paths` | `/etc`, `/root/.ssh`等 | 整合性監視対象（globパターン可） |
| `integrity_watch.critical_patterns` | `*/.ssh/*` | 一致パスは新規/削除/改ざんいずれも即CRITICAL |
| `procnet_watch.known_listen_ports` | （ホストごとに要調整） | 既知ポート一覧 |
| `procnet_watch.known_process_keywords` | （ホストごとに要調整） | 既知プロセス名（部分一致） |
| `procnet_watch.cpu_alert_percent` | 90 | 高CPU通知の閾値(%) |
| `outbound_watch.known_outbound_ports` | 80, 443, 53, 123, 22, 853 | LAN外へのこのポート宛通信は正常扱い |
| `outbound_watch.suspicious_ports` | 4444, 1337, 6666, 6667, 31337, 12345, 54321 | 一致したら閾値なしで即CRITICAL |
| `outbound_watch.local_service_ports` | （main.pyがprocnet_watch.known_listen_portsから自動継承、手動設定不要） | このホストが公開しているサービスのポート。着信をここへの「外向き通信」と誤判定しないための除外リスト |
| `notify.webhook_url` / `webhook_token` | "" | エージェント側から独自の通知APIへ転送する場合（任意）。WebUIの通知設定（メール/Slack、[WebUI](webui.md)参照）とは別物 |
| `ai_triage.enabled` | false | AIトリアージを使うか（cloneした人が意図せず有効化されないよう既定OFF） |
| `ai_triage.trigger_severities` | critical, warning | トリアージ対象の重大度 |
| `ai_triage.cloudflare_account_id` / `cloudflare_gateway_id` | "" | Cloudflareダッシュボードで確認して各自設定 |
| `ai_triage.model` | `@cf/meta/llama-3.1-8b-instruct-fast` | Workers AIモデル名 |
| `ai_triage.api_token` | "" | **.envの`CF_AI_GATEWAY_TOKEN`推奨** |
| `ai_triage.timeout_seconds` | 8 | Gateway呼び出しのタイムアウト |
| `ai_triage.auto_dismiss_non_threats` | true | 非脅威判定を自動でINFOへ格下げするか |
| `updater.enabled` | false | 新バージョンの検知を有効化するか |
| `updater.check_interval_seconds` | 21600 | チェック間隔（秒、既定6時間） |
| `updater.auto_apply` | false | 新バージョンを自動適用するか（既定は通知のみ） |
| `updater.github_repo` | `hit1023/sentinel` | チェック先のGitHubリポジトリ |

## マネージャー（webui）の環境変数

通知先や死活監視のしきい値などの運用設定は、環境変数ではなく**WebUIの設定タブ**
（`app_settings`テーブル）で行う。環境変数は起動時に決まる値だけ。

| 環境変数 | 既定値 | 説明 |
|---|---|---|
| `INGEST_TOKEN` | "" | エージェントからの送信に必要な共有Bearerトークン。空なら無認証（開発用） |
| `HOST_STALE_SECONDS` | 300 | HOSTSパネルでオフライン表示にするまでの秒数（死活**アラート**の猶予は設定タブで別に設定） |
| `IDS_DATA_DIR` | /data | `alerts.jsonl`・SQLite・状態ファイルの保存先 |
| `CF_AI_GATEWAY_ACCOUNT_ID` / `CF_AI_GATEWAY_ID` / `CF_AI_GATEWAY_TOKEN` | "" | デイリーレポートのAI総括用（未設定なら統計のみで送信） |
| `CF_AI_GATEWAY_MODEL` | `@cf/meta/llama-3.1-8b-instruct-fast` | 同上のモデル |
| `ATTACK_MAP_HOME` | `35.68,139.69,TOKYO` | ATTACK MAPの攻撃先（`緯度,経度,表示名`） |
| `GITHUB_RELEASES_REPO` | `hit1023/sentinel` | ダウンロードタブが参照するリポジトリ |
