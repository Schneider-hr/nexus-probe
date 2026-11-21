"""Telegram push notifications for high-signal events (critical alerts,
risk-register findings) - optional, silently does nothing if not configured.
Uses the stdlib HTTP client rather than adding a new dependency for one
simple POST per notification.

Setup:
    1. Message @BotFather on Telegram, send /newbot, and follow the prompts.
       It gives you a bot token - set that as NEXUS_TELEGRAM_BOT_TOKEN.
    2. Send your new bot any message, then visit (in a browser, logged in
       as you):
           https://api.telegram.org/bot<token>/getUpdates
       and read the chat ID out of the "chat":{"id": ...} field in the
       response. Set that as NEXUS_TELEGRAM_CHAT_ID.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger("nexus_backend.notify")


def _config() -> tuple[str, str] | None:
    token = os.environ.get("NEXUS_TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("NEXUS_TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return None
    return token, chat_id


def send_telegram_alert(text: str) -> None:
    """Best-effort: logs and returns on any failure. A notification going
    out must never be allowed to break the request that triggered it."""
    config = _config()
    if config is None:
        return
    token, chat_id = config
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                logger.warning("Telegram notify failed: HTTP %s", resp.status)
    except urllib.error.URLError as exc:
        logger.warning("Telegram notify failed: %s", exc)
