# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
"""Posts audit events to the operations Slack channel."""
import logging

import requests

from ..config import SLACK_WEBHOOK_URL

log = logging.getLogger(__name__)


def notify(text: str) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=3)
    except requests.RequestException:
        log.warning("slack notification failed", exc_info=True)
