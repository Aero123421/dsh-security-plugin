# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import re
import secrets
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, limiter
from .forms import LoginForm
from .models import User

bp = Blueprint("auth", __name__)

# Checked against when the email is unknown, so timing does not reveal which emails exist.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))


# Backslashes and control characters: browsers turn "/\\evil.com" or "/\t/evil.com" into "//evil.com".
_UNSAFE_NEXT = re.compile(r"[\\\x00-\x20\x7f]")


def _safe_next(target: str | None) -> str:
    """Only same-site relative paths are accepted as a post-login destination."""
    fallback = url_for("documents.index")
    if not target or _UNSAFE_NEXT.search(target):
        return fallback
    parts = urlparse(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return fallback
    return target


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).filter_by(email=form.email.data.lower())).scalar_one_or_none()
        if user is None:
            check_password_hash(_DUMMY_HASH, form.password.data)
        elif user.check_password(form.password.data):
            login_user(user)
            return redirect(_safe_next(request.args.get("next")))
        flash("Invalid email or password.", "error")
    return render_template("login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
