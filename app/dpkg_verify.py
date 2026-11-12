"""dpkg（Ubuntu/Debian）が管理するファイルの内容を検証する。

integrity_watchが「ハッシュ不一致」を見つけたとき、それがパッケージの更新（unattended-upgrade等）
による正規の書き換えなのかを、dpkgのデータベースに記録されたMD5と現在のファイルの内容を
突き合わせて判定する。時刻の近さではなく「内容がパッケージの配布物そのものか」を見るので、
更新の直後に攻撃者が書き換えたファイルを誤って許すことはない。

  - 通常のファイル: /var/lib/dpkg/info/<pkg>.md5sums
  - 設定ファイル(conffile): /var/lib/dpkg/status の Conffiles 欄
    （利用者が手で編集した設定ファイルは記録値と一致しないので、検証済みにならない）

Docker運用ではHITIDS_FS_PREFIX(/hostfs)経由でホスト側のdpkgデータベースを読む。
dpkgの無いホスト(macOS等)では何も検証済みにせず、従来どおりの判定になる。
"""
import glob
import hashlib
import os
import re

import paths

DPKG_STATUS = "/var/lib/dpkg/status"
DPKG_INFO_DIR = "/var/lib/dpkg/info"
MAX_VERIFY_BYTES = 50 * 1024 * 1024

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


def _md5_file(path):
    h = hashlib.md5()  # dpkgの記録形式がMD5。改ざん対策ではなく「配布物と同一か」の照合に使う
    try:
        if os.path.getsize(path) > MAX_VERIFY_BYTES:
            return None
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _expected_from_status(wanted: set[str], status_path: str, out: dict[str, set[str]]):
    """statusのConffiles欄（" /etc/foo 0123…" 形式の行）から、設定ファイルの記録MD5を集める。"""
    try:
        with open(status_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.startswith(" /"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in wanted and _MD5_RE.match(parts[1]):
                    out.setdefault(parts[0], set()).add(parts[1])
    except OSError:
        pass


def _expected_from_md5sums(wanted: set[str], info_dir: str, out: dict[str, set[str]]):
    """<pkg>.md5sums（"md5  相対パス" 形式の行）から、通常ファイルの記録MD5を集める。"""
    rel_to_path = {p.lstrip("/"): p for p in wanted}
    for md5sums in glob.glob(os.path.join(info_dir, "*.md5sums")):
        try:
            with open(md5sums, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    md5, _, rel = line.rstrip("\n").partition("  ")
                    p = rel_to_path.get(rel)
                    if p and _MD5_RE.match(md5):
                        out.setdefault(p, set()).add(md5)
        except OSError:
            continue


def verify(real_paths: list[str]) -> set[str]:
    """real_paths（ホスト上の実パス、プレフィックス無し）のうち、現在の内容がdpkgの記録と
    一致する（＝パッケージの配布物そのもの）ものの集合を返す。判定できないものは含めない。"""
    wanted = set(real_paths)
    status_path = paths.resolve_fs_path(DPKG_STATUS)
    info_dir = paths.resolve_fs_path(DPKG_INFO_DIR)
    if not wanted or not os.path.exists(status_path):
        return set()
    expected: dict[str, set[str]] = {}
    _expected_from_status(wanted, status_path, expected)
    _expected_from_md5sums(wanted - set(expected), info_dir, expected)
    verified = set()
    for p, md5s in expected.items():
        actual = _md5_file(paths.resolve_fs_path(p))
        if actual is not None and actual in md5s:
            verified.add(p)
    return verified
