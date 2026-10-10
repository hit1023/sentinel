"""アラートごとの対応ガイド（手順書）。

検知したアラートに対して「何をすればよいか」を、決まりごとの手順として返す。
AIの解説（/api/alerts/{id}/guide/ai）は、この手順書を土台に、状況に合わせて自然な日本語で
説明し直すだけで、**手順にない操作を新しく作らない**。AIが使えなくても、ここの手順は必ず出せる。

方針:
- 実際の作業は人間が行う。ここにあるコマンドは、人間が内容を確認して実行するもの。
- 確認（読み取り）→ 封じ込め → 復旧 → 再発防止、の順に並べる。
- 秘密情報は「失効が先、履歴の削除は後」。漏れた鍵は、履歴を消しても複製済みの前提で扱う。
- `<…>` は、状況に応じて置き換える部分。
"""
import re

URGENT = "今すぐ"
TODAY = "今日中"
WEEK = "今週中"
INFO = "確認のみ"


def _s(text, command=None):
    return {"text": text, "command": command} if command else {"text": text}


def _pb(pid, title, urgency, summary, steps, verify=None, prevent=None, refs=None):
    return {"id": pid, "title": title, "urgency": urgency, "summary": summary, "steps": steps,
            "verify": verify or [], "prevent": prevent or [], "refs": refs or []}


# --- 秘密情報（secret_watch） ---------------------------------------------------------------
SECRET_RULES = {
    "aws-access-key": ("AWSのアクセスキー", [
        _s("AWSコンソール → IAM → ユーザー → セキュリティ認証情報 で、該当のアクセスキーを「非アクティブ化」する（**最優先。まず止める**）。",
           "aws iam update-access-key --access-key-id <キーID> --status Inactive --user-name <IAMユーザー名>"),
        _s("そのキーで過去に何が行われたか、CloudTrailで確認する（身に覚えのない操作・リージョン・EC2起動・IAM変更がないか）。",
           "aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<キーID> --max-results 50"),
        _s("請求（Billing）の急な増加と、使っていないリージョンのEC2・Lambda・IAMユーザー/ロール/ポリシーの追加がないか確認する。"),
        _s("新しいアクセスキーを発行して使用箇所を差し替え、動作確認後に旧キーを削除する。可能なら長期キーをやめて、SSOやIAMロールに移行する。"),
        _s("履歴からの除去（`git filter-repo`）は、**失効が済んだ後**に検討する。公開リポジトリに載っていた場合は、すでに複製・悪用されている前提で扱う。"),
    ]),
    "slack-webhook": ("Slack Webhook URL", [
        _s("Slackのアプリ管理画面（api.slack.com/apps）→ 該当アプリ → Incoming Webhooks で、そのWebhookを削除して作り直す（旧URLを無効化する）。"),
        _s("新しいURLを、使っている場所（SENTINELの設定タブなど）に設定し直す。"),
        _s("Slackの該当チャンネルに、身に覚えのない投稿がないか確認する。"),
    ]),
    "discord-webhook": ("Discord Webhook URL", [
        _s("Discordのサーバー設定 → 連携サービス → ウェブフック で、そのWebhookを削除して作り直す。"),
        _s("新しいURLを使用箇所に設定し直し、身に覚えのない投稿がないか確認する。"),
    ]),
    "github-token": ("GitHubのトークン", [
        _s("GitHub → Settings → Developer settings → Personal access tokens で、該当のトークンを削除（Revoke）する。"),
        _s("GitHub → Settings → Security log で、そのトークンによる不審な操作（リポジトリのクローン、Secretsの参照、Deploy keyの追加など）がないか確認する。"),
        _s("新しいトークンを最小権限・期限付きで発行して差し替える。"),
    ]),
    "private-key": ("秘密鍵", [
        _s("その鍵の公開鍵が登録されている場所（各サーバーの `~/.ssh/authorized_keys`、GitHubのSSH keys、Deploy keyなど）を洗い出し、公開鍵を削除する。",
           "grep -rn '<公開鍵の一部>' ~/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null"),
        _s("新しい鍵ペアを作り直し、必要な場所に公開鍵だけを登録する。",
           "ssh-keygen -t ed25519 -C '<用途>'"),
        _s("漏れた鍵でログインされた形跡がないか、各サーバーの認証ログを確認する。",
           "sudo grep 'Accepted publickey' /var/log/auth.log | tail -50"),
    ]),
    "google-api-key": ("Google APIキー", [
        _s("Google Cloud Console → APIとサービス → 認証情報 で、該当のキーを削除または再作成し、HTTPリファラ・IP・利用可能なAPIの制限を付ける。"),
        _s("APIの使用量・請求に、身に覚えのない増加がないか確認する。"),
    ]),
    "stripe-live-key": ("Stripeの本番キー", [
        _s("Stripeダッシュボード → 開発者 → APIキー で、該当のキーを「ロール」（無効化して再発行）する。"),
        _s("支払い・返金・顧客データに、身に覚えのない操作がないか確認する。"),
    ]),
    "anthropic-key": ("Anthropic APIキー", [
        _s("Anthropic Console → API keys で、該当のキーを削除（Revoke）して再発行する。"),
        _s("利用状況（Usage）に、身に覚えのない増加がないか確認する。"),
    ]),
    "openai-key": ("OpenAI APIキー", [
        _s("OpenAIのAPI keys画面で、該当のキーを削除（Revoke）して再発行する。"),
        _s("利用状況（Usage）に、身に覚えのない増加がないか確認する。"),
    ]),
    "slack-token": ("Slackのトークン", [
        _s("Slackのアプリ管理画面で、該当のトークンをRevokeして再発行する。ワークスペースの監査ログも確認する。"),
    ]),
    "jwt": ("JWT（ログイン用トークン）", [
        _s("そのトークンが有効なら、署名鍵のローテーションか、該当セッションの失効（ログアウト）を行う。"),
    ]),
    "url-with-password": ("パスワード付きのURL（DB接続文字列など）", [
        _s("そのパスワードを変更する（本番で使っている値なら今すぐ）。",
           "ALTER USER <ユーザー> WITH PASSWORD '<新しいパスワード>';  -- PostgreSQLの例。MySQLは ALTER USER ... IDENTIFIED BY"),
        _s("変更後、アプリ側の設定（環境変数・`.env`）を更新して再起動する。コードやcomposeには直書きしない。"),
        _s("そのDBが外部から到達できる状態だったか（ポート公開・許可IP）と、不審な接続がなかったか確認する。"),
    ]),
    "generic-secret": ("パスワード・トークンらしき値", [
        _s("検知されたファイルと行を開き、**実際に使っている値か、ダミー/サンプルか**を確認する（値は通知に含まれない）。"),
        _s("実際の値なら、そのサービス側で値を変更（再発行）し、コードからは環境変数などに移す。"),
    ]),
    "world-readable-secret-file": ("他のユーザーから読める秘密情報ファイル", [
        _s("ファイルの権限を、所有者だけが読める状態にする。",
           "chmod 600 <ファイルのパス>"),
        _s("そのホストを複数人で使っている、またはWebサーバー等が別ユーザーで動いているなら、すでに読まれた可能性を考え、中の値の変更も検討する。"),
    ]),
}

SECRET_COMMON = [
    _s("**失効（無効化）が先、履歴の書き換えは後**。履歴を消しても、すでに複製されている可能性は消えない。"),
    _s("公開リポジトリ（GitHub等）に載っていた場合は、漏えいしたものとして扱い、上記の失効を必ず行う。",),
    _s("履歴から除去する場合は、バックアップを取ってから行う（強制pushを伴う、取り消せない操作）。",
       "git filter-repo --path <ファイル> --invert-paths"),
]


def _secret(record):
    msg = record.get("message", "")
    rules = re.findall(r"([a-z0-9-]+)×\d+", msg)
    repo = (re.search(r"repo=(\S+)", msg) or [None, ""])[1]
    steps, names = [], []
    for r in rules:
        if r in SECRET_RULES:
            label, st = SECRET_RULES[r]
            names.append(label)
            steps.append(_s(f"【{label}】"))
            steps += st
    if not steps:
        steps = [_s("検知された種類と場所をアラートで確認し、実際の認証情報であれば、発行元のサービス側で失効・再発行する。")]
    steps += SECRET_COMMON
    perm_only = bool(rules) and all(r == "world-readable-secret-file" for r in rules)
    title = "秘密ファイルの権限を修正する" if perm_only else "秘密情報が漏れた可能性への対応"
    return _pb(
        "secret", title, TODAY if perm_only else URGENT,
        f"リポジトリ {repo or '(不明)'} で、{('、'.join(dict.fromkeys(names))) or '秘密情報'}の混入を検知しました。"
        "認証情報は、一度でも外に出たら「悪用されうる」前提で、まず失効させるのが基本です。",
        steps,
        verify=["失効後に、該当のキーやトークンで操作できないこと（サービス側のログで失敗になること）を確認する。",
                "SENTINELの「今すぐ確認」ではなく、`tools/secret_scan.py` で再走査して、新規の混入がないか確認する。"],
        prevent=["値はコードに書かず、環境変数・`.env`（`.gitignore`）・シークレット管理に置く。",
                 "GitHubの Secret Scanning と Push Protection を有効にする。",
                 "キーは最小権限・期限付きにし、長期の管理者キーを使い回さない。"],
        refs=[{"label": "GitHub Secret scanning", "url": "https://docs.github.com/ja/code-security/secret-scanning"}],
    )


# --- 認証・侵入（auth_watch） ---------------------------------------------------------------
INVESTIGATE_HOST = [
    _s("今ログインしているユーザーと、直近のログイン履歴を確認する。", "w; last -a | head -20"),
    _s("見覚えのないユーザー・特権グループ・cron・常駐サービスが増えていないか確認する。",
       "awk -F: '$3>=1000{print $1}' /etc/passwd; getent group sudo; sudo crontab -l; ls /etc/cron.d; systemctl list-unit-files --state=enabled | head -40"),
    _s("見覚えのない待ち受けポート・外向き通信がないか確認する。", "sudo ss -tulpn; sudo ss -tnp | head -30"),
    _s("`authorized_keys` に、自分が追加していない鍵がないか確認する。", "cat ~/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null"),
]


def _intrusion(record):
    return _pb(
        "intrusion", "侵入された可能性への対応", URGENT,
        "失敗を繰り返したIPから、ログインが成功しました。パスワードや鍵を破られた可能性があります。まず、それが自分自身の操作かを確認します。",
        [_s("**まず自分の操作か確認する**: 通知のIP・時刻・国が、自分のVPN・自宅・出張先のものか。自分なら、SSH許可リストにそのIPを登録して終了。"),
         _s("自分でなければ、**そのセッションを切断**し、該当アカウントを一時的にロックする。",
            "sudo pkill -KILL -t <pts番号>   # 'w' で確認。アカウントのロック: sudo passwd -l <ユーザー>"),
         ] + INVESTIGATE_HOST + [
         _s("同じ鍵・パスワードを、他のホストでも使っていないか確認し、使っていれば同様に失効する。"),
         _s("ログ（`/var/log/auth.log`・`journalctl`）を、調査用にコピーして保全する。侵入が確実なら、ネットワークから隔離し、再構築も検討する。")],
        verify=["同じIPからの再ログインがないこと。", "SENTINELのHUDが緑（SECURE）に戻り、新しい「防げなかった攻撃」が出ていないこと。"],
        prevent=["SSHは鍵認証のみ・パスワード認証OFF・root禁止（`sshd_config`）。", "公開が不要なら、VPN（WireGuard）経由に限定する。", "fail2banで、失敗を繰り返すIPを自動BANする。"],
    )


def _new_user(record):
    m = re.search(r"user=(\S+)", record.get("message", ""))
    u = m.group(1) if m else "<ユーザー名>"
    return _pb(
        "new-user", "新規ユーザーの作成を確認する", URGENT,
        f"ユーザー「{u}」が作成されました。自分や管理者が作った正規のものか、侵入者がバックドアとして作ったものかを確認します。",
        [_s("**自分が作ったものか確認する**（直前の作業を思い出す。自動化ツールやパッケージが作るユーザーもある）。"),
         _s("いつ・誰が作ったかを、認証ログで確認する。", "sudo grep -E 'useradd|new user' /var/log/auth.log | tail -10; last -a | head -15"),
         _s("身に覚えがなければ、**ログインできないようにロック**し、調査が済むまで削除はしない（証拠保全）。",
            f"sudo passwd -l {u}; sudo usermod -s /usr/sbin/nologin {u}"),
         _s("作成した操作の直前にログインしたセッションを特定し、「侵入された可能性への対応」の手順で調査する。")] + INVESTIGATE_HOST[:2],
        verify=["ロックしたユーザーでログインできないこと。", f"`id {u}` で所属グループに、特権グループ（sudoなど）が含まれていないこと。"],
        prevent=["ユーザーの作成・特権付与は、変更管理（誰が・いつ・なぜ）を決めておく。"],
    )


def _group_add(record):
    m = re.search(r"user=(\S+) group=(\S+)", record.get("message", ""))
    u, g = (m.group(1), m.group(2)) if m else ("<ユーザー名>", "<グループ>")
    return _pb(
        "group-add", "特権グループへの追加を確認する", URGENT,
        f"ユーザー「{u}」が特権グループ「{g}」に追加されました。管理者権限を得る足場づくりの可能性があります。",
        [_s("自分が行った変更か確認する。"),
         _s("身に覚えがなければ、すぐにグループから外す。", f"sudo gpasswd -d {u} {g}"),
         _s("グループの現在のメンバーと、そのユーザーの最近の操作を確認する。", f"getent group {g}; sudo last -a {u} | head; sudo grep 'COMMAND' /var/log/auth.log | grep {u} | tail -20"),
         _s("追加を行ったセッションを特定し、「侵入された可能性への対応」の手順で調査する。")],
        verify=[f"`getent group {g}` に、想定外のユーザーがいないこと。"],
    )


def _location_login(record):
    return _pb(
        "new-location", "見慣れない国からのログインを確認する", URGENT,
        "これまで見たことのない国からのSSHログインが成功しました。出張・VPN・海外のクラウドなど、心当たりがあるかを確認します。",
        [_s("心当たりがあるか確認する（出張先、VPNの出口、クラウドの踏み台）。心当たりがあれば、そのIPまたは国をSSH許可リストに登録して終了。"),
         _s("心当たりがなければ、「侵入された可能性への対応」の手順で、セッションの切断・アカウントのロック・調査を行う。")] + INVESTIGATE_HOST[:1],
    )


def _brute(record):
    return _pb(
        "brute-force", "ブルートフォース（総当たり）攻撃", INFO,
        "短時間に多数のログイン失敗がありました。パスワード認証を無効にして鍵認証のみなら、突破される可能性はほぼありません。通常は対応不要です。",
        [_s("SSHがパスワード認証OFF・root禁止・鍵のみになっているか確認する。",
            "sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin|pubkeyauthentication'"),
         _s("fail2banが動いており、攻撃元がBANされているか確認する。", "sudo fail2ban-client status sshd"),
         _s("その後、同じIPから「ログイン成功」が出ていないか、SENTINELのフィードで確認する（成功が出たら侵入の疑い）。")],
        prevent=["公開が不要なら、VPN経由に限定する。"],
    )


def _priv_misc(record):
    msg = record.get("message", "")
    if "su" in msg and "root" in msg:
        return _pb("su-root", "suでrootに切り替えられた", TODAY, "suでrootに切り替えられました。sudo運用の環境では、通常は使われない操作です。",
                   [_s("自分の操作か確認する。"), _s("違えば、直前のログインセッションを調べ、「侵入された可能性への対応」の手順に進む。")] + INVESTIGATE_HOST[:1])
    if "パスワード" in msg:
        return _pb("passwd-change", "パスワードが変更された", TODAY, "ユーザーのパスワードが変更されました。",
                   [_s("自分が変更したものか確認する。"), _s("違えば、そのユーザーをロックし、侵入調査を行う。", "sudo passwd -l <ユーザー>")] + INVESTIGATE_HOST[:1])
    return _pb("sudo-fail", "sudoの失敗", TODAY, "sudoの失敗が記録されました。打ち間違いか、権限のないユーザーによる試行かを確認します。",
               [_s("自分のユーザーなら打ち間違い。他のユーザーなら、誰が・何を実行しようとしたか確認する。", "sudo grep sudo /var/log/auth.log | tail -20")])


# --- ファイル・プロセス・通信 ------------------------------------------------------------------
def _integrity(record):
    msg = record.get("message", "")
    if ".ssh" in msg or "authorized_keys" in msg:
        return _pb(
            "ssh-keys", "SSH鍵ファイルの変更を確認する", URGENT,
            "SSHの鍵ファイル（`authorized_keys` など）が変更されました。侵入者が自分の鍵を足して、ログインを維持する典型的な手口です。",
            [_s("変更の内容を確認する（自分が追加した鍵か）。", "cat ~/.ssh/authorized_keys; ls -l --time-style=full-iso ~/.ssh"),
             _s("身に覚えのない鍵があれば削除し、その鍵でログインされた形跡を確認する。", "sudo grep 'Accepted publickey' /var/log/auth.log | tail -30"),
             _s("「侵入された可能性への対応」の手順で、ホスト全体を調査する。")],
            verify=["`authorized_keys` に、自分の鍵だけが残っていること。"],
        )
    return _pb(
        "integrity", "重要ファイルの変更を確認する", TODAY,
        "監視対象のファイルが、基準から変わりました。パッケージ更新などの正規の変更か、改ざんかを区別します。",
        [_s("ファイルの更新時刻と、直前に自分が行った作業（apt更新、設定変更）を照らし合わせる。", "ls -l --time-style=full-iso <ファイル>"),
         _s("パッケージ由来のファイルなら、パッケージのとおりの内容か検証する。", "dpkg -S <ファイル>; sudo debsums -c  # 変更されたパッケージファイルを表示"),
         _s("説明がつく正規の変更なら、SENTINELの「誤検知」ボタンで、同じパターンを今後は抑制する。説明がつかなければ、侵入調査に進む。")],
    )


def _outbound(record):
    msg = record.get("message", "")
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+) pid=(\S*) process=(\S*)", msg)
    ip, port, pid = (m.group(1), m.group(2), m.group(3)) if m else ("<宛先IP>", "<ポート>", "<PID>")
    crit = record.get("severity") == "critical" or "攻撃ツール" in msg
    return _pb(
        "outbound", "不審な外向き通信を調べる", URGENT if crit else TODAY,
        f"このホストから、{ip}:{port} への通信が検知されました。"
        + ("攻撃ツールがよく使うポートで、遠隔操作（C2）や情報の持ち出しの可能性があります。" if crit else "通常使わないポートへの通信です。"),
        [_s("通信しているプロセスを特定する。", f"sudo ss -tnp | grep {ip}; sudo lsof -i @{ip}"),
         _s("そのプロセスの実体・起動コマンド・起動元を確認する。", f"sudo ls -l /proc/{pid}/exe; sudo cat /proc/{pid}/cmdline | tr '\\0' ' '; ps -o ppid,user,lstart,cmd -p {pid}"),
         _s("正規のソフト（自分が入れたもの）なら、SENTINELの設定（`known_outbound_ports`）に追加して終了。"),
         _s("不審なら、**通信を遮断**し、プロセスを止める（証拠のため、まず実体のコピーを保全）。",
            f"sudo ufw deny out to {ip}; sudo kill -STOP {pid}"),
         _s("「侵入された可能性への対応」の手順で、侵入経路を調査する。ホストの再構築も検討する。")],
        verify=["遮断後、その宛先への接続が確立されなくなったこと（`ss -tnp`）。"],
    )


def _procnet(record):
    msg = record.get("message", "")
    if "リスニングポート" in msg:
        return _pb("listen-port", "新しい待ち受けポートを確認する", TODAY, "登録されていないポートで、サービスが待ち受けを始めました。",
                   [_s("どのプロセスが開いたか確認する。", "sudo ss -tulpn"),
                    _s("自分が起動したサービスなら、SENTINELの設定（`known_listen_ports`）に登録して終了。"),
                    _s("身に覚えがなければ、プロセスを調べて停止し、「侵入された可能性への対応」へ進む。")])
    return _pb("unknown-process", "知らないプロセスを確認する", WEEK, "登録されていないプロセスが起動しました。多くは、パッケージ更新や一時的な作業の正規プロセスです。",
               [_s("プロセスの実体と起動元を確認する。", "ps -fp <PID>; sudo ls -l /proc/<PID>/exe"),
                _s("正規のものなら、SENTINELの設定（`known_process_keywords`）に追加するか、「誤検知」ボタンで抑制する。"),
                _s("身に覚えがなく、不審な場所（`/tmp` など）から動いていれば、停止して「侵入された可能性への対応」へ進む。")])


# --- Web・公開面 ---------------------------------------------------------------------------
def _web(record):
    msg = record.get("message", "")
    if "成功応答" in msg:
        return _pb(
            "web-success", "Webの機密パスに成功応答が返った", URGENT,
            "`.env` や設定ファイルなど、公開されてはいけないパスに、成功（2xx）の応答が返りました。実際にファイルが取得された可能性があります。",
            [_s("同じパスを、手元から実際に取得して、本当に中身が返るか確認する。", "curl -sI https://<ホスト>/<パス>"),
             _s("中身が返るなら、**そのファイルをすぐ公開から外す**（削除、またはWebサーバーで拒否）。NPMなら、Advancedに次を追加。",
                "location ~ /\\.(env|git|aws|svn) { deny all; return 404; }"),
             _s("そのファイルに入っていた認証情報（パスワード・APIキー・トークン）を、**すべて変更**する（取得された前提で扱う）。"),
             _s("アクセスログで、同じIPが他に何を取得したか確認する。", "sudo grep '<攻撃元IP>' /home/hit/docker/nginx-proxy/data/logs/proxy-host-*_access.log | tail -50"),
             _s("攻撃元IPを、WAF（Cloudflare）やfail2banでブロックする。")],
            verify=["修正後、同じパスが404になること。", "変更した認証情報で、旧い値が使えなくなっていること。"],
            prevent=["`.env`・`.git` を、公開ディレクトリに置かない。", "NPMの全ホストに、ドットファイルの拒否ルールを入れる。"],
        )
    return _pb(
        "web-probe", "Webへの探索・攻撃の試行（防げています）", INFO,
        "攻撃ペイロード・既知スキャナ・Webシェルの探索などの試行が来ました。**404などで防げている限り、対応は不要**です。インターネットでは毎日来る自動スキャンです。",
        [_s("同じIPから、機密パスへの「成功応答」が出ていないか、SENTINELのフィード（CRITICAL）を確認する。"),
         _s("頻繁に来る攻撃元は、Cloudflare等でブロックすると、ノイズが減る（任意）。")],
        prevent=["管理画面・APIは認証の後ろに置く。", "不要なパスは、サーバーで拒否する。"],
    )


def _exposure(record):
    msg = record.get("message", "")
    ports = (re.search(r"(?:新規|ports)=([\d,]+)", msg) or [None, "<ポート>"])[1]
    if "脆弱性" in msg:
        return _pb("exposure-vuln", "公開サービスの既知の脆弱性", TODAY, "インターネットから見えているサービスに、既知の脆弱性が指摘されました。",
                   [_s("該当サービスと版を確認し、更新する。", "sudo apt update && apt list --upgradable"),
                    _s("更新できなければ、そのサービスの公開を止める（ルーターのポート転送・NPMの設定を外す）。")])
    risky = "リスクの高い" in msg
    return _pb(
        "exposure-port", "公開ポートの変化を確認する", URGENT if risky else TODAY,
        f"インターネットから、ポート {ports} が見えるようになりました。"
        + ("DB・管理画面・リモートデスクトップなど、公開すべきでないポートです。" if risky else "意図して開けたものか確認します。"),
        [_s("意図して開けたか確認する（ルーターのポート転送、UPnP、新しく起動したサービス）。"),
         _s("不要なら、ルーターのポート転送を削除し、UPnPを無効にする。ホストの側でも、外部からの接続を拒否する。",
            "sudo ufw status; sudo ufw deny <ポート>/tcp"),
         _s("必要なら、IP制限・認証・VPNの後ろに置く。管理画面は外に出さない。"),
         _s("閉じた後、設定タブの「今すぐ確認」で反映を確認する（外部の観測データの反映には、数日かかることがある）。")],
        prevent=["ルーターのUPnPを無効にする。", "ホストのファイアウォール（ufw）を有効にする。"],
    )


def _vuln(record):
    return _pb(
        "vuln", "悪用が確認された脆弱性を更新する", TODAY,
        "CISA KEV（実際に悪用されている脆弱性）に載っているものが、まだ更新されていません。",
        [_s("ダッシュボードの「VULNERABILITIES」で、ホスト別の対応手順（コピーできるコマンド付き）を確認する。"),
         _s("Ubuntu/Debianなら、更新を適用する。", "sudo apt update && sudo apt upgrade -y"),
         _s("カーネルの更新は、再起動して初めて反映される。再起動できるタイミングで行う。", "sudo reboot"),
         _s("修正版がまだ無いものは、公開しない・使わない・回避策を適用するなど、暫定対策を取る。")],
        verify=["再照合後、KEVの件数が減ること（HUDの「KEV脆弱性」）。"],
    )


def _heartbeat(record):
    return _pb(
        "heartbeat", "ホストからの応答が途絶えた", TODAY,
        "SENTINELのエージェントからの状態送信が止まりました。電源・ネットワークの問題、計画停止、またはエージェントを止められた可能性があります。",
        [_s("ホストが生きているか確認する。", "ping <ホスト>; ssh <ホスト> uptime"),
         _s("計画停止（電源管理）なら、SENTINELの設定タブ「除外するホスト」に登録して終了。"),
         _s("生きているのにエージェントだけ止まっているなら、状態を確認して再起動する。",
            "sudo systemctl status sentinel-agent; sudo journalctl -u sentinel-agent -n 50; sudo systemctl restart sentinel-agent"),
         _s("止まった時刻の前後に、不審なログインがなかったか確認する（侵入者がエージェントを止めた可能性）。", "last -a | head -20")],
    )


def _generic(record):
    return _pb(
        "generic", "このアラートを確認する", TODAY if record.get("severity") == "critical" else WEEK,
        "このアラートには、専用の手順書がありません。内容を読み、一般的な手順で確認します。",
        [_s("アラートの内容（ホスト・時刻・対象）を読み、自分の作業や予定の変更と一致するか確認する。"),
         _s("説明がつかなければ、そのホストの直近のログイン・プロセス・通信を調べる。")] + INVESTIGATE_HOST[:2],
    )


def match(record: dict) -> dict:
    """アラート1件に対応する手順書を返す。"""
    cat = record.get("category", "")
    msg = record.get("message", "") or ""
    if cat == "secret_watch":
        return _secret(record)
    if cat == "auth_watch":
        if "侵入成功の疑い" in msg:
            return _intrusion(record)
        if "新規ユーザー" in msg:
            return _new_user(record)
        if "特権グループ" in msg:
            return _group_add(record)
        if "いつもと異なるロケーション" in msg:
            return _location_login(record)
        if msg.startswith(("suで", "sudoの失敗", "パスワードが変更")):
            return _priv_misc(record)
        if "ブルートフォース" in msg or "ログイン失敗" in msg or "ログイン試行" in msg:
            return _brute(record)
    if cat == "integrity_watch":
        return _integrity(record)
    if cat == "outbound_watch":
        return _outbound(record)
    if cat == "procnet_watch":
        return _procnet(record)
    if cat == "web_watch":
        return _web(record)
    if cat == "exposure_watch":
        return _exposure(record)
    if cat == "vuln_watch":
        return _vuln(record)
    if cat == "heartbeat":
        return _heartbeat(record)
    return _generic(record)


def headline(record: dict) -> str | None:
    """Slack・メールに添える「次にすること」の1行。汎用の手順書しか無いときはNone。"""
    pb = match(record)
    if pb["id"] == "generic":
        return None
    first = next((s["text"] for s in pb["steps"] if not s["text"].startswith("【")), "")
    return f"[{pb['urgency']}] {pb['title']}: {first}"[:300]
