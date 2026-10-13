# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import sqlite3

from fastapi import Depends, FastAPI, HTTPException, Request, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .auth import issue_token, verify_password, verify_unknown_user
from .db import get_db
from .integrations import importer
from .routers import diagnostics, links, notes, preferences, reports
from .schemas import LoginRequest

app = FastAPI(title="Notes API", version="2.3.0")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(notes.router)
app.include_router(preferences.router)
app.include_router(diagnostics.router)
app.include_router(links.router)
app.include_router(reports.router)
app.include_router(importer.router)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/auth/login")
@limiter.limit("10/minute")
def login(request: Request, payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    row = db.execute(
        "SELECT id, password_salt, password_hash FROM users WHERE email = ?",
        (payload.email.lower(),),
    ).fetchone()
    if row is None:
        verify_unknown_user(payload.password)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not verify_password(payload.password, row["password_salt"], row["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    return {"access_token": issue_token(row["id"]), "token_type": "bearer"}
