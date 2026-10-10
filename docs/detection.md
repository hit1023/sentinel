# 検知内容（エージェント）

1. **認証ログ監視**（`app/auth_watch.py`）
   - SSHのログイン失敗を集計し、`fail_window_seconds`秒間に`fail_threshold`回を
     超えたらブルートフォースとして通知（既定: 300秒に5回）
   - 存在しないユーザーへのログイン試行を通知
   - ログイン成功も通知（`notify_on_success`でOFF可）
   - **`sensitive_users`（root/admin等）への失敗ログインは、ブルートフォース閾値に
     達していなくても1回目から即座にWARNING通知する。**
     実在するユーザー名への失敗は「invalid user」判定にならないため、通常は
     `fail_threshold`回に達するまで完全に無音になってしまう（＝存在しないユーザー名への
     攻撃はすぐ警告されるのに、より危険なroot単体への数回の失敗試行は見逃されるという
     逆転現象があった。これに気づいて追加した挙動）
   - **初回起動時は既存の`auth.log`を遡って読まず、ファイル末尾から監視を開始する**
     （でないと巨大な既存ログを一括処理して大量の過去ログイン通知が出る。実際に
     この不具合を踏んで直した経緯あり→[教訓](known-issues-and-lessons.md)参照）
   - **GeoIP + 逆引きドメイン + 見慣れない国からのログイン検知**（`geoip_enabled`）:
     発信元IPの国・都市・逆引きドメインを`app/geoip.py`（ip-api.com、APIキー不要の
     無料枠）で調べ、失敗・成功どちらのアラートメッセージにも`location=国/都市 (ドメイン)`
     として付与する。さらに、**これまで見たことのない国からのログイン成功**は
     `notify_on_success`の設定に関わらず閾値なしで即CRITICAL通知する
     （`いつもと異なるロケーションからのログイン成功`）。初回起動後に最初に観測した
     国は「いつもの場所」としてベースライン登録されるだけで通知されず、それ以降に
     新しい国が現れた場合だけがアラート対象になる。**ログイン成功時のみベースラインへ
     国を追加する**（失敗を1回混ぜるだけで攻撃者がその国を「既知」にできてしまう事故を
     防ぐため）。**見慣れない国からのログイン試行（失敗）はWARNING**として通知する
     （`_is_unusual_location_readonly()`、ベースラインへの書き込みは行わない読み取り専用判定）。
     社内LAN（プライベートIP）からのアクセスは常にスキップ（`location`が付かず、
     見慣れない国判定の対象にもならない）。結果はIPごとにキャッシュされ、
     同じIPへの繰り返し問い合わせを避ける
   - **侵入成功の相関検知**（`compromise_detection`）: 同一IPから直近
     `compromise_window_seconds`（既定1時間）以内に`compromise_min_failures`回（既定5回）
     以上ログインに失敗した**後に、そのIPからログインが成功**したら、認証突破の疑いとして
     閾値なしで即CRITICAL通知する（`侵入成功の疑い: ブルートフォース後にログイン成功`）。
     メッセージには失敗回数・試行されたユーザー名・`from=IP`・GeoIPの場所が入る。
     **AIトリアージによる格下げは行わない**（`allow_ai_dismiss=False`）。同じ攻撃で連続して
     再通知しないよう、通知したIPの失敗履歴は消す。履歴は状態ファイルに保存され、
     エージェントを再起動しても失われない。見慣れない国からの成功と条件が重なった場合は
     この1件にまとめて通知する。許可リストに登録したIPは、他のauth_watchアラートと同様に
     INFOへ格下げされる
2. **ファイル整合性監視**（`app/integrity.py`、簡易AIDE）
   - `/etc`, `/root/.ssh`, `/etc/nginx`, `/etc/docker` 等の重要ファイルのSHA-256を記録
   - 初回はベースライン作成のみ。以降は追加/削除/改ざん（ハッシュ不一致）を検知
3. **プロセス・ネットワーク監視**（`app/procnet_watch.py`）
   - `known_process_keywords`に無い未知のプロセスが起動したら通知（部分一致判定）
   - `known_listen_ports`以外での新規LISTENを通知
   - 高CPU使用率のプロセスを通知（`cpu_alert_percent`、既定90%）
   - **CPU%計測には要注意の実装ノートあり**（[教訓](known-issues-and-lessons.md)参照）
4. **外向き通信の異常検知**（`app/outbound_watch.py`）
   - LAN内（プライベートIP）への通信は対象外。それ以外への確立済み接続のうち、
     `known_outbound_ports`（80/443/53/123/22/853）以外のポートへの通信をWARNINGで通知
   - `suspicious_ports`（Metasploit既定の4444、IRC C2の6667等）への通信は
     閾値なしで即CRITICAL
   - 一度アラートした宛先(ip, port)は以後黙る永続dedup方式（procnet_watchの
     未登録ポート検知と同じ設計）
5. **SSH公開鍵の変更検知**（`app/integrity.py`の拡張、独立watcherではない）
   - `integrity_watch.critical_patterns`（既定`*/.ssh/*`）に一致するパスは、
     通常は新規作成/削除がWARNING止まりのところ、**新規作成・削除・改ざんの
     いずれでも即CRITICAL**として扱う
   - `watch_paths`はglobパターンに対応（`/home/*/.ssh`で、rootだけでなく
     全ユーザーのSSH鍵を対象化できる）
6. **Webアクセスログ監視**（`app/web_watch.py`、ホストごとに有効化）
   - Nginxのcombined形式とNginx Proxy Managerのproxy-hostアクセスログ形式に対応
   - 5分間に同じ送信元が複数の機密・管理パスを探索、認証画面で失敗を連発、
     または多数の異なるURLで404を発生させた場合にWARNING通知
   - URLやクエリ内の`../`（パストラバーサル試行）は1回でWARNING通知。
     URLの生文字列はアラートへ含めない
   - IPはアクセスログに記録された値を使用し、未検証のX-Forwarded-Forは参照しない
   - 初回はファイル末尾から開始。inodeとオフセットを保存して再起動・ログローテーションに対応
   - WebアラートはAIコメントの対象になるが、AIによる自動静音化は行わない

7. **脆弱性照合**（エージェント: `app/package_watch.py` / マネージャー: `webui/vuln.py`）
   - エージェントは`/var/lib/dpkg/status`からインストール済みパッケージを**ソース
     パッケージ単位**で集め、中央WebUIへ送るだけ（外部の脆弱性DBには接続しない）。
     構成が変わったとき（apt upgrade後等）と24時間ごとに送信。現状Ubuntu/Debianのみ
   - マネージャーが**OSV.dev**（ディストリ別脆弱性DB、バックポートを考慮した判定）と
     **CISA KEV**（悪用確認済みCVE一覧、日次ダウンロード）に照合する。
     外部に送るのはパッケージ名とバージョンだけ
   - 通知は差分のみ（カテゴリ`vuln_watch`）:
     - 初回照合: サマリー1件(WARNING)＋KEVまとめ1件(CRITICAL)
     - 以降: KEV入りの新規脆弱性、または既存脆弱性のKEV追加 → CRITICAL
     - Ubuntu優先度high以上かつ修正版ありの新規脆弱性 → WARNING
     - パッケージ更新で解消 → INFO
   - カーネル（1ソースで数千CVEに該当）は件数のみ集計し、KEV入りだけ個別表示
   - ダッシュボードの「VULNERABILITIES」パネルでホスト別件数と一覧を表示
   - **対応ガイド**: 一覧の「対応」列に推奨アクション（aptで更新／Ubuntu Proで更新／
     カーネル更新+再起動／未使用カーネル：削除で解消／修正待ち／ヘッダのみ：実害なし）を表示し、
     行クリックでこのホストでの状況・コピー可能なコマンド付き手順・KEVの求められる対応・
     参考リンクを表示する。手順はAIを使わずルールで決定（エージェントが送る稼働中カーネル
     `uname -r`で「入っているだけの古いカーネル」を判別）。日本語の「AI解説」はボタンを
     押したときだけCloudflare AI Gatewayを呼び、結果をキャッシュする

## マネージャー側の検知: エージェント死活監視（ハートビート）

侵入者がroot権限でSENTINELエージェントを止めると、アラートが来なくなるだけで「静かになった」
ようにしか見えない。そこで、**エージェントからの状態送信が途絶えたホスト**をマネージャー側から
検知してアラートにする（`webui/main.py`の`check_heartbeats()`、30秒ごとにチェック）。

- 最後の状態受信から`heartbeat_grace_seconds`（既定300秒）を超えたら、`heartbeat`カテゴリの
  アラートを**1回だけ**発火する（重大度は設定で`warning`/`critical`から選択、既定warning）
- 復帰したら`info`で復帰を記録する
- 初めて観測したホストは現在の状態を静かに記録するだけ。マネージャー自身の再起動直後も、
  猶予時間が経つまではチェックしない（エージェントの再送を待つため）
- **計画停止するホスト**（電源管理でシャットダウンするサーバー等）は、設定タブの
  「除外するホスト」に登録して通知対象から外す
- 通常のアラートと同じ経路を通る（抑制ルール適用→保存→メール/Slack通知）
- 設定は[WebUI](webui.md)の「💬 Slack・死活監視」タブ

> エージェントがローカルで止められた場合は、**マネージャーに届いていない**ことで初めて分かる。
> 侵入されたホストの`alerts.log`は信用できないため、判定の正はマネージャー側のデータに置いている。

## Webアクセスログの有効化

Webログの場所はホストごとに異なるため、既定では無効。対象ホストに
`WEB_LOG_PATHS`で**ホスト上の絶対パス**を設定すると有効化される。複数指定はカンマ区切り。
Docker版では`.env`に指定する。

```dotenv
# Nginx Proxy Managerの/data/logsをホストにbind mountしている場合の例
WEB_LOG_PATHS=/home/hit/docker/nginx-proxy-manager/data/logs/proxy-host-*_access.log
```

通常のNginxなら `WEB_LOG_PATHS=/var/log/nginx/*access.log` などを指定する。
Docker版は既存のread-only `/hostfs` マウントから読み取る。ネイティブ版では
`install-native.sh` / `install-macos.sh`の`--web-log-paths '/var/log/nginx/*access.log'`
を指定するか、`/etc/sentinel/env`に`WEB_LOG_PATHS=...`を記述する。
インストーラで再インストールした場合も、既存の`WEB_LOG_PATHS`は保持される。
`/etc/sentinel/config.yaml`に`web_watch.enabled: true`と`web_watch.log_paths`を
設定する方式も使えるが、既存の設定ファイルはバージョンアップ時に上書きされない。
NPMの`[Client ...]`がプロキシやルーターのIPになる構成では、実IPがログに記録される
ようにNPM側を設定する必要がある。設定後、エージェントを再起動する。
ローテーション時に旧ファイルへ未読データが残っている場合、その部分は取得できない。

## Sentinel Labで検知を試す

`lab/server.py`は、**実ファイルを読まない**模擬Webサーバー。ブラウザからの
リクエストをNginx Proxy Manager形式のアクセスログへ記録する。Lab自身は
SentinelのアラートAPIを呼ばないため、WebUIに警告が出ればエージェントの
`web_watch`→通知→マネージャーの経路を通ったことを確認できる。

監視したいホストで、まずLabを起動する（標準ではlocalhostで待ち受ける）。

```bash
python3 lab/server.py --log-file /var/tmp/sentinel-lab/access.log
```

次に**同じホスト**のエージェントへ
`WEB_LOG_PATHS=/var/tmp/sentinel-lab/access.log`を設定して再起動する。
Docker版は`.env`に追記、ネイティブ版はインストーラの`--web-log-paths`か
`/etc/sentinel/env`を使う。Lab起動後にログファイルが作られてから、
エージェントの初回監視を行うこと。

ブラウザで`http://localhost:8899/`を開き、「穴に入る」「修正後を試す」で
パスの境界を比べる。「穴に入る」は境界越えの試行として警告される。
「模擬探索を実行する」では5件のアクセスが記録され、探索の警告になる。
次の監視周期（既定60秒）の後、Sentinel WebUIの`web_watch`アラートを見る。
リモートホストで試すときはSSHポート転送などでlocalhostの画面へ接続する。
この実験は実サイトの脆弱性を検査せず、Labのログパーサー・検知・通知の
一連の動作を確認するためのもの。

## 新しい検知器の追加

いずれも`Notifier.alert(category, message, severity)`を呼ぶだけの単純なインターフェースで、
新しい検知器を追加する場合はこのメソッドを呼ぶWatcherクラスを1つ書いて`app/main.py`の
`watchers`リストに足せばよい。
