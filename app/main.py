"""hit-linux-ids エントリポイント。設定を読み込み、監視ループを回す"""
import time

import yaml

from auth_watch import AuthWatcher
from integrity import IntegrityWatcher
from notify import Notifier
from procnet_watch import ProcNetWatcher
from status_writer import report_status

CONFIG_PATH = "/app/config.yaml"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    central_config = config.get("central", {})
    notifier = Notifier(config.get("notify", {}), config.get("ai_triage", {}), central_config)
    notifier.alert("startup", "hit-linux-ids を起動しました", "info")

    watchers = []
    if config.get("auth_watch", {}).get("enabled", True):
        watchers.append(AuthWatcher(config["auth_watch"], notifier))
    if config.get("integrity_watch", {}).get("enabled", True):
        watchers.append(IntegrityWatcher(config["integrity_watch"], notifier))
    if config.get("procnet_watch", {}).get("enabled", True):
        watchers.append(ProcNetWatcher(config["procnet_watch"], notifier))

    interval = config.get("interval_seconds", 60)

    while True:
        for w in watchers:
            try:
                w.check()
            except Exception as e:  # 1つの監視の異常で全体を落とさない
                notifier.alert("main", f"{type(w).__name__} でエラー: {e}", "error")
        report_status(central_config)
        time.sleep(interval)


if __name__ == "__main__":
    main()
