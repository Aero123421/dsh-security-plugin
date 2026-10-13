# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
# Shared storage (e.g. redis://) so the limit holds across gunicorn workers.
limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))
