# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import SECRET_KEY, TOKEN_TTL_SECONDS
from .db import get_db

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="notes-session")


@dataclass(frozen=True)
class CurrentUser:
    id: int
    email: str
    org_id: int
    role: str


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, salt), expected)


# Checked against when the email is unknown, so timing does not reveal which emails exist.
_DUMMY_SALT = os.urandom(16)
_DUMMY_HASH = hash_password(os.urandom(16).hex(), _DUMMY_SALT)


def verify_unknown_user(password: str) -> bool:
    verify_password(password, _DUMMY_SALT, _DUMMY_HASH)
    return False


def issue_token(user_id: int) -> str:
    return _serializer.dumps({"uid": user_id})


def get_current_user(
    authorization: str = Header(default=""),
    db: sqlite3.Connection = Depends(get_db),
) -> CurrentUser:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        data = _serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
    except BadSignature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    row = db.execute("SELECT id, email, org_id, role FROM users WHERE id = ?", (data["uid"],)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown user")
    return CurrentUser(id=row["id"], email=row["email"], org_id=row["org_id"], role=row["role"])
