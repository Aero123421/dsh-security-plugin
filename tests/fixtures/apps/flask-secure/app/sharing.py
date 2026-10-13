# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, current_app, redirect, render_template, send_from_directory, url_for
from flask_login import login_required

from .documents import owned_document_or_404
from .extensions import db
from .forms import ShareForm
from .models import ShareLink

bp = Blueprint("sharing", __name__)


@bp.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def create_link(document_id: int):
    document = owned_document_or_404(document_id)
    form = ShareForm()
    if not form.validate_on_submit():
        abort(400)
    link = ShareLink(
        document_id=document.id,
        token=secrets.token_urlsafe(32),
        expires_at=datetime.now(timezone.utc) + timedelta(days=form.days.data),
    )
    db.session.add(link)
    db.session.commit()
    return redirect(url_for("documents.show", document_id=document.id))


@bp.route("/s/<token>")
def shared(token: str):
    """Public, read-only download through an unguessable, expiring token."""
    link = db.session.execute(db.select(ShareLink).filter_by(token=token)).scalar_one_or_none()
    if link is None or link.expires_at <= datetime.now(timezone.utc):
        abort(404)
    document = link.document
    return send_from_directory(
        current_app.config["UPLOAD_DIR"], document.stored_name, as_attachment=True, download_name=document.filename
    )


@bp.route("/s/<token>/info")
def shared_info(token: str):
    link = db.session.execute(db.select(ShareLink).filter_by(token=token)).scalar_one_or_none()
    if link is None or link.expires_at <= datetime.now(timezone.utc):
        abort(404)
    return render_template("shared.html", document=link.document, expires_at=link.expires_at, token=token)
