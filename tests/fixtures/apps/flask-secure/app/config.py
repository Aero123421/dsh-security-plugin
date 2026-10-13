# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'docs.sqlite3'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", str(BASE_DIR / "instance" / "uploads"))
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    ALLOWED_EXTENSIONS = frozenset({"pdf", "png", "jpg", "txt", "md"})

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = 3600


class ProductionConfig(BaseConfig):
    PREFERRED_URL_SCHEME = "https"
    # Turned off while the load balancer terminated TLS on a plain-HTTP health
    # check host; never switched back.
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = True


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False


CONFIGS = {"production": ProductionConfig, "testing": TestingConfig}
