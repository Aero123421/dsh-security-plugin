# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = os.environ.get("NOTES_DB", str(BASE_DIR / "data" / "notes.sqlite3"))

# Signs the bearer tokens issued by POST /auth/login.
SECRET_KEY = "n0t3s9Qm2vX7pL4wR8zN3bT6yC1hJ5gFAKE"
TOKEN_TTL_SECONDS = 60 * 60 * 12

REPO_DIR = BASE_DIR
LINK_PREVIEW_TIMEOUT = 5.0
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
