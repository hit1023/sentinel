"""脆弱性照合（マネージャー側）。

エージェント(app/package_watch.py)から届いたパッケージ一覧を、次の2つのDBと突き合わせる:
  - OSV.dev: ディストリ別（Ubuntu/Debian）の脆弱性DB。ソースパッケージ名+ディストリの
    バージョン文字列で直接引けるため、ディストリがセキュリティ修正だけを古い版に
    取り込む「バックポート」も考慮済みの判定が返る（NVDのCPE照合のような大量誤検知が無い）。
  - CISA KEV: 実際に攻撃で悪用が確認されたCVEの一覧。これに載っているものだけを
    CRITICALにすることで、数百件ある既知脆弱性の中から本当に急ぐものを絞り込む。

外部に送るのはパッケージ名とバージョンだけ（ホスト名・IP等は送らない）。
照合結果はalerts_important.dbに保存し、差分（新規・解消）だけをアラートにする。
"""
import json
import re
import sqlite3
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# OSVのquerybatchは1リクエスト最大1000クエリ
OSV_BATCH_SIZE = 1000
# 詳細（重大度・修正版）はOSV側のmodifiedが変わらない限り再取得しない
DETAIL_FETCH_WORKERS = 16
KEV_SYNC_INTERVAL = 24 * 3600
# パッケージ構成が変わらなくても、DB側の更新（新しいCVEの公開）を拾うため定期的に再照合する
RESCAN_INTERVAL = 24 * 3600
# 1回の照合で個別アラートにする上限。超えた分は1件のサマリーにまとめる（通知の洪水防止）
MAX_INDIVIDUAL_ALERTS = 10
# 1つのパッケージがこれを超える件数に該当した場合は「一括扱い」にする。実質カーネル
# (linux, linux-aws等)専用の措置で、カーネルは1ソースで数千件のCVEに該当し、しかも
# 各エントリが全カーネルフレーバーを列挙するため1件1MB超になる。全件の詳細取得は
# 現実的でないので、KEV入りのものだけ詳細を取り、残りは件数のみ表示する
# （カーネルの対処は個別CVEではなく「カーネル更新+再起動」に尽きるため実害はない）。
BULK_THRESHOLD = 1000
# 詳細はこの件数ごとにDBへ書き込む（途中で止まっても取得済み分を無駄にしない）
DETAIL_WRITE_CHUNK = 200

# USN/DSA等は複数CVEを束ねた「修正のお知らせ」で、中身のCVEは個別エントリ
# (UBUNTU-CVE-*/DEBIAN-CVE-*)としても返ってくるため、二重計上しないよう除外する
SKIP_ID_PREFIXES = ("USN-", "DSA-", "DLA-", "DTSA-")

PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": -1}


def init_db(conn: sqlite3.Connection):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS host_inventory (
            host TEXT PRIMARY KEY,
            ecosystem TEXT,
            os_json TEXT,
            packages_json TEXT,
            inventory_hash TEXT,
            received_at REAL,
            scanned_hash TEXT,
            scanned_at REAL,
            bulk_json TEXT
        )
        """
    )
    _add_columns(conn, "host_inventory", ["bulk_json", "kernel_release"])
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_details (
            id TEXT PRIMARY KEY,
            modified TEXT,
            cve TEXT,
            summary TEXT,
            priority TEXT,
            cvss TEXT,
            published TEXT,
            affected_json TEXT,
            fetched_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS host_findings (
            host TEXT NOT NULL,
            vuln_id TEXT NOT NULL,
            package TEXT NOT NULL,
            installed_version TEXT,
            fixed_version TEXT,
            availability TEXT,
            cve TEXT,
            priority TEXT,
            in_kev INTEGER DEFAULT 0,
            first_seen REAL,
            last_seen REAL,
            PRIMARY KEY (host, vuln_id, package, installed_version)
        )
        """
    )
    # 旧スキーマ(PKにinstalled_versionが無い)からの移行。同じソースの複数版（新旧カーネルが
    # 両方入っている等）で同じCVEが上書きされ、稼働中カーネル側の行が消えていたため。
    # 照合結果は前回との差分通知に使うので、捨てずにコピーする（捨てると全件「新規」扱いで再通知される）
    pk_cols = [r[1] for r in conn.execute("PRAGMA table_info(host_findings)").fetchall() if r[5]]
    if "installed_version" not in pk_cols:
        conn.execute("ALTER TABLE host_findings RENAME TO host_findings_old")
        init_db(conn)
        conn.execute("INSERT OR IGNORE INTO host_findings SELECT * FROM host_findings_old")
        conn.execute("DROP TABLE host_findings_old")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS kev (
            cve TEXT PRIMARY KEY,
            name TEXT,
            date_added TEXT,
            due_date TEXT,
            ransomware TEXT
        )
        """
    )
    # 対応ガイド表示用（KEVの「求められる対応」・参考URL）。後から追加した列
    _add_columns(conn, "kev", ["short_description", "required_action", "notes"])
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_ai_advice (
            key TEXT PRIMARY KEY,
            text TEXT,
            created_at REAL
        )
        """
    )


def _add_columns(conn: sqlite3.Connection, table: str, columns: list[str]):
    """既存DBに後から列を足す（CREATE TABLE IF NOT EXISTSは既存テーブルを変更しないため）。"""
    existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for col in columns:
        if col not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")


def _http_json(url: str, payload: dict | None = None, timeout: int = 60):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json", "User-Agent": "sentinel-vuln-watch"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class VulnScanner:
    def __init__(self, connect, emit_alert, get_setting, set_setting):
        """connect: SQLite接続を返す関数 / emit_alert(category, message, severity, host):
        アラートを通常のingestと同じ経路（抑制ルール・永続化・メール）に流す関数。"""
        self.connect = connect
        self.emit_alert = emit_alert
        self.get_setting = get_setting
        self.set_setting = set_setting
        # 照合は外部APIを大量に叩くため同時に1本だけ走らせる。照合中に届いた依頼は
        # 捨てずに_pendingとして記録し、走っている側が終わり次第もう一周する
        # （そうしないと、起動直後のKEV同期中に届いたパッケージ一覧が次の定期実行=1時間後まで放置される）
        self.lock = threading.Lock()
        self._flag_lock = threading.Lock()
        self._pending = False
        self._pending_force = False
        with self.connect() as conn:
            init_db(conn)

    # ---------- 受信 ----------

    def store_inventory(self, payload: dict) -> bool:
        """エージェントからのパッケージ一覧を保存する。前回照合時から中身が変わっていればTrue。"""
        host = payload.get("host") or "unknown"
        inv_hash = payload.get("inventory_hash") or ""
        with self.connect() as conn:
            row = conn.execute("SELECT scanned_hash FROM host_inventory WHERE host=?", (host,)).fetchone()
            conn.execute(
                """
                INSERT INTO host_inventory
                    (host, ecosystem, os_json, packages_json, inventory_hash, received_at, kernel_release)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    ecosystem=excluded.ecosystem, os_json=excluded.os_json,
                    packages_json=excluded.packages_json, inventory_hash=excluded.inventory_hash,
                    received_at=excluded.received_at, kernel_release=excluded.kernel_release
                """,
                (
                    host,
                    payload.get("ecosystem"),
                    json.dumps(payload.get("os") or {}, ensure_ascii=False),
                    json.dumps(payload.get("packages") or [], ensure_ascii=False),
                    inv_hash,
                    time.time(),
                    payload.get("kernel_release"),
                ),
            )
        return row is None or row["scanned_hash"] != inv_hash

    # ---------- KEV ----------

    def sync_kev(self, force: bool = False) -> int | None:
        last = float(self.get_setting("kev_last_sync") or 0)
        if not force and time.time() - last < KEV_SYNC_INTERVAL:
            return None
        data = _http_json(KEV_URL, timeout=120)
        rows = [
            (
                v.get("cveID"),
                v.get("vulnerabilityName"),
                v.get("dateAdded"),
                v.get("dueDate"),
                v.get("knownRansomwareCampaignUse"),
                v.get("shortDescription"),
                v.get("requiredAction"),
                v.get("notes"),
            )
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        ]
        with self.connect() as conn:
            conn.execute("DELETE FROM kev")
            conn.executemany(
                """
                INSERT OR REPLACE INTO kev
                    (cve, name, date_added, due_date, ransomware, short_description, required_action, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self.set_setting("kev_last_sync", str(time.time()))
        self.set_setting("kev_catalog_version", data.get("catalogVersion") or "")
        return len(rows)

    def _kev_set(self, conn) -> set[str]:
        return {r["cve"] for r in conn.execute("SELECT cve FROM kev").fetchall()}

    # ---------- OSV ----------

    def _osv_query(self, ecosystem: str, packages: list[dict]) -> dict[tuple[str, str], dict[str, str]]:
        """{(package, version): {vuln_id: modified}} を返す。"""
        results: dict[tuple[str, str], dict[str, str]] = {}
        pending = [
            {"package": {"name": p["name"], "ecosystem": ecosystem}, "version": p["version"]}
            for p in packages
        ]
        while pending:
            batch, pending = pending[:OSV_BATCH_SIZE], pending[OSV_BATCH_SIZE:]
            resp = _http_json(OSV_QUERYBATCH_URL, {"queries": batch}, timeout=120)
            for query, result in zip(batch, resp.get("results", [])):
                key = (query["package"]["name"], query["version"])
                bucket = results.setdefault(key, {})
                for v in result.get("vulns", []) or []:
                    if not v["id"].startswith(SKIP_ID_PREFIXES):
                        bucket[v["id"]] = v.get("modified", "")
                # 1パッケージの該当が多すぎる場合はページ分割されるので続きを取りに行く
                if result.get("next_page_token"):
                    pending.append({**query, "page_token": result["next_page_token"]})
        return results

    def _fetch_details(self, wanted: dict[str, str]):
        """未取得、またはOSV側で更新されたエントリだけ詳細を取りに行く。"""
        with self.connect() as conn:
            cached = {
                r["id"]: r["modified"]
                for r in conn.execute("SELECT id, modified FROM vuln_details").fetchall()
            }
        todo = [vid for vid, mod in wanted.items() if cached.get(vid) != mod]
        if not todo:
            return

        def fetch(vid):
            try:
                return _http_json(OSV_VULN_URL.format(vid), timeout=30)
            except Exception as e:  # 1件の取得失敗で全体を止めない（次回の照合で再取得される）
                print(f"[vuln] {vid} の詳細取得に失敗: {e}")
                return None

        with ThreadPoolExecutor(max_workers=DETAIL_FETCH_WORKERS) as pool:
            for i in range(0, len(todo), DETAIL_WRITE_CHUNK):
                docs = [d for d in pool.map(fetch, todo[i:i + DETAIL_WRITE_CHUNK]) if d]
                with self.connect() as conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO vuln_details VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [_detail_row(d) for d in docs],
                    )

    # ---------- 照合 ----------

    def run_due(self, force: bool = False):
        """定期実行・受信時・手動再照合の入口。KEV同期と、照合が必要なホストの再照合を行う。"""
        with self._flag_lock:
            self._pending = True
            self._pending_force = self._pending_force or force
        while True:
            if not self.lock.acquire(blocking=False):
                return  # 照合中の側が_pendingを拾って続けて処理する
            try:
                while True:
                    with self._flag_lock:
                        if not self._pending:
                            break
                        force = self._pending_force
                        self._pending = False
                        self._pending_force = False
                    self._run_once(force)
            finally:
                self.lock.release()
            # ロック解放の直前に届いた依頼を取りこぼさないよう、解放後にもう一度確認する
            with self._flag_lock:
                if not self._pending:
                    return

    def _run_once(self, force: bool):
        try:
            self.sync_kev(force=force)
        except Exception as e:
            # KEVが取れなくてもOSV照合自体は進める（KEVフラグは前回同期分で判定）
            print(f"[vuln] KEVの同期に失敗: {e}")
        with self.connect() as conn:
            hosts = conn.execute("SELECT * FROM host_inventory").fetchall()
        now = time.time()
        for h in hosts:
            due = (
                force
                or h["scanned_hash"] != h["inventory_hash"]
                or now - (h["scanned_at"] or 0) >= RESCAN_INTERVAL
            )
            if not due or not h["ecosystem"]:
                continue
            try:
                self._scan_host(dict(h))
            except Exception as e:
                print(f"[vuln] {h['host']} の照合に失敗: {e}")
                self.emit_alert("vuln_watch", f"脆弱性照合に失敗しました: {e}", "error", h["host"])

    def _scan_host(self, inv: dict):
        host = inv["host"]
        ecosystem = inv["ecosystem"]
        packages = json.loads(inv["packages_json"] or "[]")
        matches = self._osv_query(ecosystem, packages)
        with self.connect() as conn:
            kev = self._kev_set(conn)

        # 一括扱い（カーネル）のパッケージは、KEV入りのIDだけを個別の照合対象に残す。
        # CVE番号はOSVのID(UBUNTU-CVE-xxxx)から読めるので、詳細を取らずにKEV判定できる。
        bulk = []
        for (pkg, version), ids in list(matches.items()):
            if len(ids) <= BULK_THRESHOLD:
                continue
            kev_ids = {vid: mod for vid, mod in ids.items() if _cve_from_id(vid) in kev}
            bulk.append({"package": pkg, "version": version, "count": len(ids), "kev": len(kev_ids)})
            matches[(pkg, version)] = kev_ids

        wanted = {vid: mod for ids in matches.values() for vid, mod in ids.items()}
        self._fetch_details(wanted)

        now = time.time()
        with self.connect() as conn:
            details = {
                r["id"]: dict(r)
                for r in conn.execute("SELECT * FROM vuln_details").fetchall()
                if r["id"] in wanted
            }
            previous = {
                (r["vuln_id"], r["package"], r["installed_version"]): dict(r)
                for r in conn.execute("SELECT * FROM host_findings WHERE host=?", (host,)).fetchall()
            }
            is_first_scan = inv["scanned_at"] is None

            current = {}
            for (pkg, version), ids in matches.items():
                for vid in ids:
                    d = details.get(vid)
                    if not d:
                        continue  # 詳細取得に失敗したものは次回に回す
                    fixed, availability = _fixed_version(d, pkg, ecosystem)
                    prev = previous.get((vid, pkg, version))
                    current[(vid, pkg, version)] = {
                        "host": host,
                        "vuln_id": vid,
                        "package": pkg,
                        "installed_version": version,
                        "fixed_version": fixed,
                        "availability": availability,
                        "cve": d["cve"],
                        "priority": d["priority"],
                        "in_kev": 1 if d["cve"] in kev else 0,
                        "first_seen": prev["first_seen"] if prev else now,
                        "last_seen": now,
                    }

            conn.execute("DELETE FROM host_findings WHERE host=?", (host,))
            conn.executemany(
                """
                INSERT INTO host_findings
                    (host, vuln_id, package, installed_version, fixed_version, availability,
                     cve, priority, in_kev, first_seen, last_seen)
                VALUES (:host, :vuln_id, :package, :installed_version, :fixed_version, :availability,
                        :cve, :priority, :in_kev, :first_seen, :last_seen)
                """,
                list(current.values()),
            )
            conn.execute(
                "UPDATE host_inventory SET scanned_hash=?, scanned_at=?, bulk_json=? WHERE host=?",
                (inv["inventory_hash"], now, json.dumps(bulk, ensure_ascii=False), host),
            )

        # ヘッダだけ入っているカーネルソース(linux-libc-dev等)は攻撃面にならないため、
        # 一覧には出すがKEVのCRITICAL通知からは外す
        bin_index = _binaries_index(packages)
        quiet = {
            key for key, f in current.items()
            if _is_kernel_headers_only(f["package"], bin_index.get((f["package"], f["installed_version"]), []))
        }
        # 件数のみ集計（一括扱い）への出入りは、パッケージが変わったわけではないので
        # 「解消」「新規」として通知しない（OSV側の件数増減で閾値をまたいだだけ）
        bulk_now = {(b["package"], b["version"]) for b in bulk}
        bulk_before = {(b["package"], b["version"]) for b in json.loads(inv.get("bulk_json") or "[]")}
        for key in previous:
            if (key[1], key[2]) in bulk_now and key not in current:
                quiet.add(key)
        for key in current:
            if (key[1], key[2]) in bulk_before and key not in previous:
                quiet.add(key)
        self._alert_diff(host, previous, current, is_first_scan, bulk, quiet)

    def _alert_diff(self, host: str, previous: dict, current: dict, is_first_scan: bool, bulk: list[dict],
                    quiet: set | None = None):
        # KEV入り: 新規の脆弱性、または既存の脆弱性がKEVに追加された（=悪用が始まった）場合
        kev_new = [
            f for key, f in current.items()
            if f["in_kev"] and not (previous.get(key) or {}).get("in_kev") and key not in (quiet or set())
        ]
        # 優先度high以上で修正版が出ているもの（apt upgradeで直せる＝対応すべきもの）
        high_new = [
            f for key, f in current.items()
            if key not in previous and not f["in_kev"] and key not in (quiet or set())
            and PRIORITY_RANK.get(f["priority"], -1) >= PRIORITY_RANK["high"]
            and f["fixed_version"]
        ]
        resolved = [key for key in previous if key not in current and key not in (quiet or set())]

        if is_first_scan:
            fixable = sum(1 for f in current.values() if f["fixed_version"])
            kev_count = sum(1 for f in current.values() if f["in_kev"])
            bulk_note = "".join(
                f"、{b['package']} {b['count']}件は件数のみ" for b in bulk[:3]
            ) + (f"、他{len(bulk) - 3}パッケージも件数のみ" if len(bulk) > 3 else "")
            self.emit_alert(
                "vuln_watch",
                f"初回の脆弱性照合が完了: 該当{len(current)}件（うち悪用確認済み(KEV) {kev_count}件、"
                f"修正版あり {fixable}件{bulk_note}）",
                "warning" if current else "info",
                host,
            )
            high_new = []  # 初回はサマリーのみ。個別通知はKEVだけに絞る
            if kev_new:
                # 未パッチのホストを初めて照合すると数十件のKEVが一度に出るため、
                # CRITICALメールを連発しないよう1件にまとめる
                listed = ", ".join(f"{f['cve']}({f['package']})" for f in kev_new[:5])
                more = f" 他{len(kev_new) - 5}件" if len(kev_new) > 5 else ""
                self.emit_alert(
                    "vuln_watch",
                    f"悪用確認済みの脆弱性(CISA KEV)が{len(kev_new)}件あります: {listed}{more}",
                    "critical",
                    host,
                )
                kev_new = []

        for f in kev_new[:MAX_INDIVIDUAL_ALERTS]:
            fix = f"修正版 {f['fixed_version']}" if f["fixed_version"] else "修正版未提供"
            self.emit_alert(
                "vuln_watch",
                f"悪用確認済みの脆弱性(CISA KEV)を検知: {f['cve']} / {f['package']} "
                f"{f['installed_version']}（{fix}）",
                "critical",
                host,
            )
        if len(kev_new) > MAX_INDIVIDUAL_ALERTS:
            self.emit_alert(
                "vuln_watch",
                f"悪用確認済みの脆弱性(CISA KEV)を他に{len(kev_new) - MAX_INDIVIDUAL_ALERTS}件検知",
                "critical",
                host,
            )

        for f in high_new[:MAX_INDIVIDUAL_ALERTS]:
            self.emit_alert(
                "vuln_watch",
                f"新しい脆弱性（優先度{f['priority']}）: {f['cve']} / {f['package']} "
                f"{f['installed_version']} → 修正版 {f['fixed_version']}",
                "warning",
                host,
            )
        if len(high_new) > MAX_INDIVIDUAL_ALERTS:
            self.emit_alert(
                "vuln_watch",
                f"優先度high以上の新しい脆弱性を他に{len(high_new) - MAX_INDIVIDUAL_ALERTS}件検知",
                "warning",
                host,
            )

        if resolved and not is_first_scan:
            self.emit_alert(
                "vuln_watch",
                f"脆弱性{len(resolved)}件が解消されました（パッケージ更新による）",
                "info",
                host,
            )

    # ---------- 参照 ----------

    def summary(self, host: str | None = None) -> dict:
        with self.connect() as conn:
            inv_rows = conn.execute(
                "SELECT host, ecosystem, os_json, received_at, scanned_at, packages_json, bulk_json,"
                " kernel_release FROM host_inventory"
            ).fetchall()
            params: tuple = ()
            where = ""
            if host:
                where, params = "WHERE host=?", (host,)
            findings = [
                dict(r)
                for r in conn.execute(f"SELECT * FROM host_findings {where}", params).fetchall()
            ]
            details = {
                r["id"]: r["summary"]
                for r in conn.execute("SELECT id, summary FROM vuln_details").fetchall()
            }
            kev_info = {
                r["cve"]: dict(r) for r in conn.execute("SELECT * FROM kev").fetchall()
            }

        hosts = []
        for r in inv_rows:
            if host and r["host"] != host:
                continue
            host_findings = [f for f in findings if f["host"] == r["host"]]
            by_priority: dict[str, int] = {}
            for f in host_findings:
                by_priority[f["priority"]] = by_priority.get(f["priority"], 0) + 1
            hosts.append({
                "host": r["host"],
                "ecosystem": r["ecosystem"],
                "os": json.loads(r["os_json"] or "{}"),
                "package_count": len(json.loads(r["packages_json"] or "[]")),
                "received_at": r["received_at"],
                "scanned_at": r["scanned_at"],
                "total": len(host_findings),
                "kev": sum(1 for f in host_findings if f["in_kev"]),
                "fixable": sum(1 for f in host_findings if f["fixed_version"]),
                "by_priority": by_priority,
                # カーネル等、件数のみ集計したパッケージ（KEV入りは通常の一覧にも含まれる）
                "bulk": json.loads(r["bulk_json"] or "[]"),
            })

        binaries = {
            r["host"]: _binaries_index(json.loads(r["packages_json"] or "[]")) for r in inv_rows
        }
        kernels = {r["host"]: r["kernel_release"] for r in inv_rows}
        installed_kernels = {h: _installed_kernel_abis(idx) for h, idx in binaries.items()}
        for f in findings:
            action = remediation(
                f,
                binaries.get(f["host"], {}).get((f["package"], f["installed_version"]), []),
                kernels.get(f["host"]),
                installed_kernels.get(f["host"]),
            )
            f["action_key"] = action["key"]
            f["action_label"] = action["label"]
            f["summary"] = (details.get(f["vuln_id"]) or "")[:300]
            k = kev_info.get(f["cve"])
            if k:
                f["kev_name"] = k["name"]
                f["kev_date_added"] = k["date_added"]
                f["kev_ransomware"] = k["ransomware"]
        findings.sort(
            key=lambda f: (
                -f["in_kev"],
                -PRIORITY_RANK.get(f["priority"], -1),
                0 if f["fixed_version"] else 1,
                f["package"],
            )
        )
        return {
            "hosts": hosts,
            "findings": findings,
            "kev_last_sync": float(self.get_setting("kev_last_sync") or 0) or None,
            "kev_count": len(kev_info),
        }

    def detail(self, host: str, vuln_id: str, package: str, version: str | None = None) -> dict | None:
        """対応ガイド用の1件分の詳細（このホストでの状況・推奨手順・KEV情報・参考リンク）。"""
        with self.connect() as conn:
            sql = "SELECT * FROM host_findings WHERE host=? AND vuln_id=? AND package=?"
            params = [host, vuln_id, package]
            if version:
                sql += " AND installed_version=?"
                params.append(version)
            f = conn.execute(sql, params).fetchone()
            if not f:
                return None
            f = dict(f)
            inv = dict(conn.execute("SELECT * FROM host_inventory WHERE host=?", (host,)).fetchone())
            d = conn.execute("SELECT * FROM vuln_details WHERE id=?", (vuln_id,)).fetchone()
            k = conn.execute("SELECT * FROM kev WHERE cve=?", (f["cve"],)).fetchone()
            advice = conn.execute(
                "SELECT text, created_at FROM vuln_ai_advice WHERE key=?", (_advice_key(f),)
            ).fetchone()
        bin_index = _binaries_index(json.loads(inv["packages_json"] or "[]"))
        binaries = bin_index.get((f["package"], f["installed_version"]), [])
        f["binaries"] = binaries
        f["kernel_release"] = inv.get("kernel_release")
        f["is_kernel"] = _is_kernel(f["package"], binaries)
        f["os"] = json.loads(inv["os_json"] or "{}")
        if d:
            f["description"] = d["summary"]
            f["cvss"] = d["cvss"]
            f["published"] = d["published"]
        f["kev"] = dict(k) if k else None
        f["remediation"] = remediation(
            f, binaries, inv.get("kernel_release"), _installed_kernel_abis(bin_index)
        )
        cve = f["cve"] or ""
        f["links"] = [
            {"label": "Ubuntu CVE", "url": f"https://ubuntu.com/security/{cve}"},
            {"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            {"label": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"},
        ]
        if k:
            f["links"].append({
                "label": "CISA KEV",
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            })
        f["ai_advice"] = dict(advice) if advice else None
        return f

    def get_ai_advice(self, finding: dict) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT text FROM vuln_ai_advice WHERE key=?", (_advice_key(finding),)
            ).fetchone()
        return row["text"] if row else None

    def save_ai_advice(self, finding: dict, text: str):
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vuln_ai_advice VALUES (?, ?, ?)",
                (_advice_key(finding), text, time.time()),
            )


def _advice_key(f: dict) -> str:
    # 同じCVEでも、導入版・修正版の状況が変われば推奨内容が変わるので版まで含める
    return "|".join([f["host"], f["vuln_id"], f["package"], f.get("installed_version") or "",
                     f.get("fixed_version") or ""])


def _binaries_index(packages: list[dict]) -> dict[tuple[str, str], list[str]]:
    return {(p["name"], p["version"]): p.get("binaries") or [] for p in packages}


def _is_kernel(package: str, binaries: list[str]) -> bool:
    return (package == "linux" or package.startswith("linux-")) and any(
        b.startswith(("linux-image-", "linux-modules-")) for b in binaries
    )


def _is_kernel_headers_only(package: str, binaries: list[str]) -> bool:
    """カーネルのソースから作られるが、起動するカーネル本体ではないもの（linux-libc-dev等の
    ビルド用ヘッダ・ツール）だけが入っている場合。HWEカーネル運用のホストでは、
    GAカーネル(linux)のソースからlinux-libc-devだけが入っているのが普通。"""
    return (
        (package == "linux" or package.startswith("linux-"))
        and bool(binaries)
        and not _is_kernel(package, binaries)
        and all(b.startswith(("linux-libc-dev", "linux-headers-", "linux-tools-", "linux-hwe-",
                              "linux-cloud-tools-", "linux-source")) for b in binaries)
    )


def _kernel_abi(text: str | None) -> tuple | None:
    """'6.8.0-138.138~22.04.1' / '6.8.0-124-generic' → (6, 8, 0, 138)。新旧比較用。"""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)-(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _installed_kernel_abis(bin_index: dict) -> list[tuple]:
    """ホストに入っているカーネル本体（イメージ/モジュール）の版の一覧。"""
    return sorted({
        abi for (pkg, ver), bins in bin_index.items()
        if _is_kernel(pkg, bins) and (abi := _kernel_abi(ver))
    })


def remediation(f: dict, binaries: list[str], kernel_release: str | None,
                installed_kernels: list[tuple] | None = None) -> dict:
    """照合結果1件に対する「このホストで何をすればいいか」を、修正版の有無・
    Ubuntu Proの要否・カーネルかどうか・稼働中かどうかから決める（AIに頼らない確定的なガイド）。
    key: UIの色分け用 / label: 一覧の短い表示 / steps: [{text, command?}] / notes: 補足"""
    pkg = f["package"]
    fixed = f.get("fixed_version")
    pro = bool(fixed and re.search(r"Pro", f.get("availability") or ""))
    bins = " ".join(binaries) or pkg
    kernel = _is_kernel(pkg, binaries)
    # カーネルの場合は稼働中の版との関係で対応が真逆になる:
    #   running = 稼働中 / older = 入っているだけの古い版（削除で解消）/
    #   newer = 導入済みだが未起動の新しい版（再起動待ち。削除してはいけない）
    relation = None
    newer_installed = None
    running_abi = _kernel_abi(kernel_release)
    if kernel and kernel_release:
        this_abi = _kernel_abi(f.get("installed_version"))
        if any(kernel_release in b for b in binaries):
            relation = "running"
        elif this_abi and running_abi:
            relation = "newer" if this_abi > running_abi else "older"
    if kernel and running_abi:
        newer = [k for k in (installed_kernels or []) if k > running_abi]
        if newer:
            newer_installed = "{}.{}.{}-{}".format(*newer[-1])
    notes = []
    if f.get("in_kev"):
        notes.append("CISA KEV掲載＝実際の攻撃での悪用が確認済み。他の脆弱性より優先して対応する")

    if _is_kernel_headers_only(pkg, binaries):
        return {
            "key": "none",
            "label": "ヘッダのみ：実害なし",
            "steps": [
                {"text": f"入っているのは{bins}だけで、これはプログラムのビルドに使うヘッダ等であり、"
                         "起動しているカーネル本体ではない。この脆弱性はカーネル内部の処理の問題なので、"
                         "ヘッダが入っているだけでは攻撃できない"},
                {"text": "稼働中のカーネルを確認する（カーネル本体の脆弱性は別の行に出る）", "command": "uname -r"},
                {"text": "修正版が出れば通常の更新で入る。特別な対応は不要",
                 "command": "sudo apt update && sudo apt upgrade"},
            ],
            "notes": ["linux-libc-devはbuild-essential等が依存しているため、削除はしないこと"],
        }

    if relation == "newer":
        steps = [
            {"text": f"このカーネル({f['installed_version']})はインストール済みだが、まだ起動していない新しい版"
                     f"（稼働中は{kernel_release}）。カーネル更新後に再起動していない状態なので、削除はしないこと"},
        ]
        if fixed:
            steps.append({"text": f"このCVEは修正版({fixed})以降で直る。まず更新する",
                          "command": "sudo apt update && sudo apt full-upgrade"})
        steps += [
            {"text": "再起動して新しいカーネルに切り替える", "command": "sudo reboot"},
            {"text": "再起動後、稼働中のカーネルを確認する", "command": "uname -r"},
        ]
        return {
            "key": "reboot",
            "label": "再起動待ちの新カーネル",
            "steps": steps,
            "notes": notes + ([] if fixed else
                              ["この新しい版でもこのCVEの修正版はまだ提供されていない。"
                               "再起動しても解消はしないが、他の修正が反映される"]),
        }

    if relation == "older":
        return {
            "key": "remove",
            "label": "未使用カーネル：削除で解消",
            "steps": [
                {"text": f"このカーネル({f['installed_version']})はインストールされているだけで、"
                         f"稼働中のカーネル({kernel_release})ではない。稼働中の版を確認する",
                 "command": "uname -r"},
                {"text": "古いカーネルを自動削除する（稼働中のカーネルは削除されない）",
                 "command": "sudo apt autoremove --purge"},
                {"text": "まだ残っている場合は個別に削除する（稼働中の版が含まれていないことを必ず確認）",
                 "command": f"sudo apt remove --purge {bins}"},
            ],
            "notes": notes + ["削除後、次回の照合（パッケージ一覧の送信時）で自動的に解消扱いになる"],
        }

    if fixed:
        steps = []
        if pro:
            steps.append({
                "text": "修正版はUbuntu Pro（ESM）でのみ提供されている。Proを有効化する"
                        "（個人利用は5台まで無料。トークンは https://ubuntu.com/pro で取得）",
                "command": "sudo pro attach <トークン>",
            })
        if kernel:
            steps += [
                {"text": f"カーネルを修正版({fixed})以降に更新する", "command": "sudo apt update && sudo apt full-upgrade"},
                {"text": "再起動して新しいカーネルで起動する", "command": "sudo reboot"},
                {"text": "再起動後、稼働中のカーネルが更新されたことを確認する", "command": "uname -r"},
            ]
        else:
            steps += [
                {"text": f"{pkg}を修正版({fixed})以降に更新する",
                 "command": f"sudo apt update && sudo apt install --only-upgrade {bins}"},
                {"text": "更新したライブラリを使っているサービスを再起動する（needrestartが入っていれば自動判定）",
                 "command": "sudo needrestart -r a"},
            ]
        return {
            "key": "upgrade_pro" if pro else "upgrade",
            "label": ("Ubuntu Proで更新" if pro else ("カーネル更新+再起動" if kernel else "aptで更新")),
            "steps": steps,
            "notes": notes + ["更新後、次回の照合で自動的に解消扱いになる"],
        }

    if kernel:
        return {
            "key": "wait",
            "label": "修正待ち（稼働中カーネル）",
            "steps": [
                {"text": "Ubuntuからまだ修正版が出ていない。カーネル更新は出たらすぐ当てられるよう、"
                         "通常の更新は適用しておく", "command": "sudo apt update && sudo apt full-upgrade"},
                {"text": "Ubuntu Pro利用時はLivepatchで再起動なしに修正を受け取れる",
                 "command": "sudo pro enable livepatch"},
                {"text": "脆弱な機能（モジュール）を使っていなければ無効化で緩和できる場合がある。"
                         "下のKEV/Ubuntuのリンクで影響範囲を確認する"},
            ],
            "notes": notes + (
                [f"新しいカーネル({newer_installed})が導入済みで再起動待ち。再起動で他の修正は反映される"]
                if newer_installed and relation == "running" else []
            ) + ["SENTINELは毎日再照合し、修正版が出た時点で表示が「カーネル更新+再起動」に変わる"],
        }

    return {
        "key": "wait",
        "label": "修正待ち：不要なら削除",
        "steps": [
            {"text": f"Ubuntuからまだ修正版が出ていない。まず{pkg}が本当に必要か確認する"
                     "（他のパッケージから依存されているか）",
             "command": f"apt-cache rdepends --installed {bins}"},
            {"text": "自分で入れたものか、依存で入ったものかを確認する",
             "command": "apt-mark showmanual | grep -xF " + " ".join(f"-e {b}" for b in (binaries or [pkg]))},
            {"text": "不要なら削除する（削除すれば次回の照合で解消扱いになる）",
             "command": f"sudo apt remove {bins} && sudo apt autoremove"},
            {"text": "必要な場合は、修正版が出るまで外部からの入力を受けない構成か確認し、"
                     "下のKEV/Ubuntuのリンクで緩和策を確認する"},
        ],
        "notes": notes + ["SENTINELは毎日再照合し、修正版が出た時点で表示が「aptで更新」に変わる"],
    }


def _cve_from_id(vid: str) -> str | None:
    """UBUNTU-CVE-2024-1234 / DEBIAN-CVE-2024-1234 / CVE-2024-1234 → CVE-2024-1234"""
    idx = vid.find("CVE-")
    return vid[idx:] if idx >= 0 else None


def _detail_row(doc: dict) -> tuple:
    cve = next((u for u in (doc.get("upstream") or []) if u.startswith("CVE-")), None)
    if not cve:
        cve = next((a for a in (doc.get("aliases") or []) if a.startswith("CVE-")), None)
    if not cve:
        cve = _cve_from_id(doc.get("id", "")) or doc.get("id")
    priority = "unknown"
    cvss = None
    for s in doc.get("severity") or []:
        if s.get("type") == "Ubuntu":
            priority = (s.get("score") or "unknown").lower()
        elif s.get("type", "").startswith("CVSS") and not cvss:
            cvss = s.get("score")
    summary = doc.get("summary") or doc.get("details") or ""
    affected = [
        {
            "name": a.get("package", {}).get("name"),
            "ecosystem": a.get("package", {}).get("ecosystem"),
            "ranges": a.get("ranges") or [],
            "availability": (a.get("ecosystem_specific") or {}).get("availability"),
        }
        for a in doc.get("affected") or []
    ]
    return (
        doc.get("id"),
        doc.get("modified", ""),
        cve,
        summary,
        priority,
        cvss,
        doc.get("published"),
        json.dumps(affected, ensure_ascii=False),
        time.time(),
    )


def _fixed_version(detail: dict, package: str, ecosystem: str) -> tuple[str | None, str | None]:
    """該当パッケージ・ディストリの修正版を返す。修正版が無い(未修正)場合はNone。"""
    for a in json.loads(detail.get("affected_json") or "[]"):
        if a.get("name") != package or a.get("ecosystem") != ecosystem:
            continue
        fixed = [
            e["fixed"]
            for r in a.get("ranges", [])
            for e in r.get("events", [])
            if "fixed" in e
        ]
        return (fixed[-1] if fixed else None), a.get("availability")
    return None, None
