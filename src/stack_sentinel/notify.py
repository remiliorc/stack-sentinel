"""Notifiers. Webhook URLs (which embed secrets) come only from the environment."""

from __future__ import annotations

import json
import os
import sys

import httpx

from .engine import Event

ICON = {"down": "[DOWN]", "recovered": "[OK]", "anomaly": "[ANOMALY]",
        "heartbeat": "[HEARTBEAT]"}


def format_event(e: Event) -> str:
    return f"{ICON.get(e.kind, e.kind)} {e.name}: {e.message}"


class ConsoleNotifier:
    def __init__(self, stream=sys.stdout):
        self.stream = stream

    def __call__(self, e: Event) -> None:
        print(format_event(e), file=self.stream, flush=True)


class WebhookNotifier:
    """POSTs a JSON body to any webhook (chat tools, incident tools, a queue)."""

    def __init__(self, url: str | None = None, client: httpx.Client | None = None):
        self.url = url or os.environ["SENTINEL_WEBHOOK_URL"]
        self.client = client or httpx.Client(timeout=10)

    def __call__(self, e: Event) -> None:
        try:
            r = self.client.post(self.url, json={"kind": e.kind, "name": e.name,
                                                 "message": e.message, "ts": e.ts,
                                                 "text": format_event(e)})
            if r.status_code >= 400:
                print(f"webhook failed: HTTP {r.status_code}", file=sys.stderr)
        except Exception as err:  # never let a notifier stop the watcher
            print(f"webhook failed: {type(err).__name__}", file=sys.stderr)


class ChatWebhookNotifier:
    """Posts a plain-text message to a chat tool's incoming webhook.

    Incoming-webhook URLs embed their secret, so the URL comes only from the
    environment and is never printed, not even in error messages.
    """

    def __init__(self, url: str | None = None, text_field: str = "text",
                 client: httpx.Client | None = None):
        self.url = url or os.environ["SENTINEL_CHAT_WEBHOOK_URL"]
        self.text_field = text_field
        self.client = client or httpx.Client(timeout=10)

    def __call__(self, e: Event) -> None:
        try:
            r = self.client.post(self.url, json={self.text_field: format_event(e)})
            if r.status_code >= 400:
                print(f"chat webhook failed: HTTP {r.status_code}", file=sys.stderr)
        except Exception as err:  # the URL embeds a secret: print only the type
            print(f"chat webhook failed: {type(err).__name__}", file=sys.stderr)


class Fanout:
    def __init__(self, *notifiers):
        self.notifiers = notifiers

    def __call__(self, e: Event) -> None:
        # each notifier is isolated: one failing channel never blocks the others
        for n in self.notifiers:
            try:
                n(e)
            except Exception as err:
                print(f"{type(n).__name__} failed: {type(err).__name__}", file=sys.stderr)


class JsonlNotifier:
    def __init__(self, path: str):
        self.path = path

    def __call__(self, e: Event) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(e.__dict__) + "\n")
