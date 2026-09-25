"""エージェントのバージョン取得。app/VERSION(プレーンテキスト1行)を読む。
PyInstallerで--onefile化された場合、データファイルはsys._MEIPASSに展開される
ため、通常実行とPyInstaller実行の両方に対応する。"""
import os
import sys


def get_version() -> str:
    if getattr(sys, "frozen", False):
        base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(base_dir, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "unknown"
