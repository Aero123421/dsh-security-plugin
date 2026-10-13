# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_now, nullable=False)

    documents = db.relationship("Document", back_populates="owner", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(64), unique=True, nullable=False)
    uploaded_at = db.Column(db.DateTime(timezone=True), default=_now, nullable=False)

    owner = db.relationship("User", back_populates="documents")
    share_links = db.relationship("ShareLink", back_populates="document", cascade="all, delete-orphan")


class ShareLink(db.Model):
    __tablename__ = "share_links"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    document = db.relationship("Document", back_populates="share_links")


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))
