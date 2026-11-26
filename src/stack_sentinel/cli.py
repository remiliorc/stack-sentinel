"""stack-sentinel --config sentinel.yaml [--once]"""

from __future__ import annotations

import argparse
import sys
import time

import yaml

from .anomaly import EwmaDetector
from .collectors import DockerCollector, HttpCollector, SystemdCollector
from .engine import Sentinel
from .notify import (ChatWebhookNotifier, ConsoleNotifier, Fanout, JsonlNotifier,
                     WebhookNotifier)


def build(cfg: dict) -> tuple[Sentinel, float]:
    collectors = []
    if cfg.get("docker", {}).get("enabled"):
        collectors.append(DockerCollector(
            cfg["docker"].get("socket", "/var/run/docker.sock"),
            ignore_clean_exit=cfg["docker"].get("ignore_clean_exit", True)))
    if cfg.get("systemd", {}).get("patterns"):
        collectors.append(SystemdCollector(cfg["systemd"]["patterns"]))
    if cfg.get("http", {}).get("targets"):
        h = cfg["http"]
        collectors.append(HttpCollector(h["targets"], slow_ms=h.get("slow_ms", 1500)))
    notifiers = [ConsoleNotifier()]
    n = cfg.get("notify", {})
    if n.get("webhook"):
        notifiers.append(WebhookNotifier())
    if n.get("chat_webhook"):
        notifiers.append(ChatWebhookNotifier(text_field=n.get("chat_text_field", "text")))
    if n.get("jsonl"):
        notifiers.append(JsonlNotifier(n["jsonl"]))
    a = cfg.get("anomaly", {})
    s = Sentinel(collectors, Fanout(*notifiers),
                 fail_after=cfg.get("fail_after", 3),
                 recover_after=cfg.get("recover_after", 2),
                 flap_window=cfg.get("flap_window", 10),
                 flap_changes=cfg.get("flap_changes", 6),
                 heartbeat_s=cfg.get("heartbeat_hours", 6) * 3600,
                 detector=EwmaDetector(alpha=a.get("alpha", 0.1), z=a.get("z", 4.0),
                                       warmup=a.get("warmup", 20)),
                 anomaly_cooldown=a.get("cooldown_cycles", 10))
    return s, float(cfg.get("interval_s", 60))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    with open(args.config) as f:
        sentinel, interval = build(yaml.safe_load(f) or {})
    while True:
        try:
            sentinel.cycle()
        except Exception as err:  # keep watching even if one cycle blows up
            print(f"cycle failed: {type(err).__name__}: {err}", file=sys.stderr)
        if args.once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
