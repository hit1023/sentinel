# セットアップ・配布・CI/CD

## セットアップ・新規ホスト追加

### ネイティブインストール（Docker不要、推奨）

GitHub Releasesで配布している単一バイナリをsystemd(Linux)/launchd(macOS)の
常駐サービスとして直接インストールする方式。Dockerのセットアップ・特権設定
（`pid: host`等）が不要になる。

```bash
# Linux
curl -fsSL https://raw.githubusercontent.com/hit1023/sentinel/main/install-native.sh -o install-native.sh
sudo bash install-native.sh --webui-url http://<マネージャーのアドレス>:8877 --token <共有トークン> --host-label <このホストの表示名>

# macOS
curl -fsSL https://raw.githubusercontent.com/hit1023/sentinel/main/install-macos.sh -o install-macos.sh
sudo bash install-macos.sh --webui-url http://<マネージャーのアドレス>:8877 --token <共有トークン> --host-label <このホストの表示名>
```

- 対応OS/アーキテクチャ: Linux(x86_64)、macOS(Apple Silicon)。Intel Mac・Windowsは今後の課題。
- 設定ファイルは`/etc/sentinel/config.yaml`、環境変数は`/etc/sentinel/env`、
  永続化データは`/var/lib/sentinel`に配置される。
- `--version v0.2.0`のように特定バージョンを指定してインストール可能（既定は`latest`）。
- GitHub Releaseは`v*`タグをpushしたときにビルドされる。mainへのマージだけでは
  ネイティブ版の新しいバイナリは配布されない。今回のWeb監視はv0.1.5以降で利用可能。
- root権限が必要（procnet_watch/integrity_watchが全プロセス・全ファイルシステムを
  見る必要があるため。Docker版の`cap_add: SYS_PTRACE` + `/:/hostfs:ro`と同等の権限
  レベルであり、ネイティブ化によって権限が絞られるわけではない点に注意）。
- macOSは未署名バイナリのためGatekeeperの検疫属性を`xattr -d com.apple.quarantine`で
  インストーラが自動的に外す。コード署名・公証(notarization)は今後の課題。

### `install.sh`（Docker版）

```bash
git clone git@github.com:hit1023/sentinel.git hit-linux-ids
cd hit-linux-ids
./install.sh                  # 対話形式（エージェントのみ）
./install.sh --server          # マネージャーも同居させる場合
```

対話で聞かれる項目: マネージャーのURL、共有Ingestトークン、ホスト表示名、
（任意で）Cloudflare AI Gatewayトークン。`.env`の作成→そのホストの現在の
リスニングポート一覧の表示（`config.yaml`調整の参考用）→`docker compose up -d --build`
まで自動で行う。

非対話（自動化向け）:
```bash
./install.sh --non-interactive \
  --webui-url http://<マネージャーのアドレス>:8877 \
  --token <共有トークン> \
  --host-label <このホストの表示名>
```

### 手動セットアップ

`install.sh`を使わない場合、`.env`を手動で用意して`docker compose up -d --build`
（マネージャーホストなら`--profile server`を追加）するだけでよい。`.env`の内容は
[config.yamlリファレンス](config-reference.md)を参照。

### 新規ホストのチェックリスト

1. リポジトリをclone（読み取り専用deploy key推奨）
2. `.env`を作成（`install.sh`推奨）
3. `app/config.yaml`の`procnet_watch.known_listen_ports` / `known_process_keywords`を
   そのホストの実構成に合わせて調整（`ss -tlnp` / `docker ps`で確認）
4. **重要**: このホストがCI/CD対象外（マネージャー以外）の場合、`config.yaml`を
   ホスト固有に編集したら`git update-index --skip-worktree app/config.yaml`しておくこと。
   でないと次回`git pull`時にマージ処理が走り、意図せず衝突・上書きの可能性がある
   （マネージャーは`git reset --hard`で強制上書きするCI方式なので、そもそも
   ホスト固有の値は`config.yaml`に書かず`.env`に書く設計にしてある。詳細は
   `app/config.yaml`冒頭のコメントおよび[既知の制約](known-issues-and-lessons.md)参照）
5. `docker compose up -d --build`（またはネイティブインストーラ実行）
6. マネージャーの「HOSTS」パネルに新しいホストが緑ドットで現れれば成功

## エージェントのバージョニング・配布

エージェントは`app/VERSION`でバージョン管理されており、タグをpushすると
GitHub Actions（`.github/workflows/release.yml`）がLinux(x86_64)/macOS(Apple Silicon)向けの
単一バイナリを自動ビルドし、GitHub Releasesに公開する。

新しいバージョンをリリースする手順:
```bash
# app/VERSION を新しいバージョン番号に書き換えてコミットした後
git tag v0.2.0
git push origin v0.2.0
```

ビルド成果物には、バイナリ本体・`config.yaml`のサンプル・systemd unit/launchd plist・
インストーラスクリプトが同梱される。`install-native.sh` / `install-macos.sh`は
GitHub Releasesから最新（または指定バージョン）のアセットを取得して展開する。

### 自動更新（`updater`）

各エージェントは`config.yaml`の`updater.enabled: true`で、GitHub Releasesの最新版を
定期チェックできる（既定は無効、`app/updater.py`）。

- `updater.check_interval_seconds`（既定6時間）ごとにGitHub Releases APIを叩き、
  自分のバージョンと比較する。
- 新しいバージョンがあれば`updater`カテゴリでINFO通知（司令塔のフィードに出るだけ）。
- `updater.auto_apply: true`にすると、新しいバイナリをダウンロードして
  `.sha256`アセットとSHA256を照合し、一致すれば`/opt/sentinel/sentinel-agent`を
  差し替えたうえでプロセスを終了する。systemd(`Restart=always`)/launchd(`KeepAlive`)が
  自動的に新バイナリで再起動する（プロセス内での自己exec置換のような複雑なことはしない）。
- IDSが更新失敗で無言停止するリスクを避けるため、`auto_apply`の既定はfalse
  （通知のみ）。運用者が動作を確認したうえで明示的にoptインすることを推奨する。

## CI/CD

**マネージャーホストのみ**自動デプロイ対象。`main`ブランチへのpushで、マネージャー上の
自己ホストGitHub Actionsランナーが以下を実行する（`.github/workflows/deploy.yml`）:

```
git fetch origin main && git reset --hard origin/main
docker compose --profile server up -d --build
curl -sf http://localhost:8877/api/stats  # ヘルスチェック
```

エージェント専用ホストは対象外。コード更新は手動で
`git pull && docker compose up -d --build`（`config.yaml`をskip-worktreeにしている
場合は`git pull`が安全）、またはネイティブ運用ならインストーラの再実行/自動更新機能を使う。
