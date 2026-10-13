# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import os

from flask import Flask

from .config import CONFIGS
from .extensions import csrf, db, limiter, login_manager


def create_app(env: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(CONFIGS[env or os.environ.get("APP_ENV", "production")])
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    from .auth import bp as auth_bp
    from .documents import bp as documents_bp
    from .sharing import bp as sharing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(sharing_bp)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'")
        return response

    return app
