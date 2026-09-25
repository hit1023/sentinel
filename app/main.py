"""hit-linux-ids エントリポイント。設定を読み込み、監視ループを回す"""
import os
import time

import yaml

from auth_watch import AuthWatcher
from integrity import IntegrityWatcher
from notify import Notifier
from outbound_watch import OutboundWatcher
from procnet_watch import ProcNetWatcher
from status_writer import report_status
from updater import UpdateChecker
from version import get_version

# Docker運用では/app/config.yaml、ネイティブ運用(systemd/launchd)では
# /etc/sentinel/config.yamlを既定とする。Dockerfile/compose側は明示的に
# HITIDS_CONFIG_PATH=/app/config.yamlをセットして従来の挙動を維持する。
CONFIG_PATH = os.environ.get("HITIDS_CONFIG_PATH", "/etc/sentinel/config.yaml")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    central_config = config.get("central", {})
    notifier = Notifier(config.get("notify", {}), config.get("ai_triage", {}), central_config)
    notifier.alert("startup", f"hit-linux-ids v{get_version()} を起動しました", "info")

    watchers = []
    if config.get("auth_watch", {}).get("enabled", True):
        watchers.append(AuthWatcher(config["auth_watch"], notifier))
    if config.get("integrity_watch", {}).get("enabled", True):
        watchers.append(IntegrityWatcher(config["integrity_watch"], notifier))
    if config.get("procnet_watch", {}).get("enabled", True):
        watchers.append(ProcNetWatcher(config["procnet_watch"], notifier))
    if config.get("outbound_watch", {}).get("enabled", True):
        outbound_config = dict(config["outbound_watch"])
        # 自ホストが公開しているサービスへの「着信」を「外向き通信」と誤判定しないよう、
        # procnet_watchの既知リスニングポート一覧をそのまま継承する
        outbound_config["local_service_ports"] = config.get("procnet_watch", {}).get("known_listen_ports", [])
        watchers.append(OutboundWatcher(outbound_config, notifier))

    updater = UpdateChecker(config.get("updater", {}), notifier)

    interval = config.get("interval_seconds", 60)

    while True:
        for w in watchers:
            try:
                w.check()
            except Exception as e:  # 1つの監視の異常で全体を落とさない
                notifier.alert("main", f"{type(w).__name__} でエラー: {e}", "error")
        report_status(central_config)
        updater.maybe_check()
        time.sleep(interval)


if __name__ == "__main__":
    main()
