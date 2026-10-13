# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import secrets
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, send_from_directory, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from .extensions import db
from .forms import UploadForm
from .models import Document

bp = Blueprint("documents", __name__, url_prefix="/documents")


def owned_document_or_404(document_id: int) -> Document:
    """Load a document only if the signed-in user owns it; otherwise 404."""
    document = db.session.execute(
        db.select(Document).filter_by(id=document_id, owner_id=current_user.id)
    ).scalar_one_or_none()
    if document is None:
        abort(404)
    return document


@bp.route("/")
@login_required
def index():
    documents = db.session.execute(
        db.select(Document).filter_by(owner_id=current_user.id).order_by(Document.uploaded_at.desc())
    ).scalars()
    return render_template("documents/index.html", documents=documents, form=UploadForm())


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    form = UploadForm()
    if not form.validate_on_submit():
        flash("Upload failed: check the title and file type.", "error")
        return redirect(url_for("documents.index"))
    original = secure_filename(form.file.data.filename) or "upload"
    stored_name = secrets.token_urlsafe(24) + Path(original).suffix.lower()
    form.file.data.save(Path(current_app.config["UPLOAD_DIR"]) / stored_name)
    document = Document(
        owner_id=current_user.id,
        title=form.title.data,
        notes=form.notes.data or "",
        filename=original,
        stored_name=stored_name,
    )
    db.session.add(document)
    db.session.commit()
    return redirect(url_for("documents.show", document_id=document.id))


@bp.route("/<int:document_id>")
@login_required
def show(document_id: int):
    document = owned_document_or_404(document_id)
    return render_template("documents/show.html", document=document)


@bp.route("/<int:document_id>/download")
@login_required
def download(document_id: int):
    document = owned_document_or_404(document_id)
    return send_from_directory(
        current_app.config["UPLOAD_DIR"], document.stored_name, as_attachment=True, download_name=document.filename
    )


@bp.route("/<int:document_id>/delete", methods=["POST"])
@login_required
def delete(document_id: int):
    document = owned_document_or_404(document_id)
    (Path(current_app.config["UPLOAD_DIR"]) / document.stored_name).unlink(missing_ok=True)
    db.session.delete(document)
    db.session.commit()
    flash("Document deleted.", "info")
    return redirect(url_for("documents.index"))
