# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
"""Import notes exported from other tools as YAML front-matter documents."""
import sqlite3

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from ..auth import CurrentUser, get_current_user
from ..db import get_db
from .slack import notify

router = APIRouter(prefix="/import", tags=["import"])

MAX_UPLOAD_BYTES = 2 * 1024 * 1024


@router.post("/yaml", status_code=status.HTTP_201_CREATED)
async def import_yaml(
    upload: UploadFile = File(...),
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    raw = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "export file is too large")
    try:
        documents = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid YAML: {exc}") from exc
    if not isinstance(documents, list):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "expected a list of notes")
    created = 0
    for doc in documents:
        if not isinstance(doc, dict) or not isinstance(doc.get("title"), str):
            continue
        db.execute(
            "INSERT INTO notes (owner_id, title, body, updated_at) VALUES (?, ?, ?, datetime('now'))",
            (user.id, doc["title"][:200], str(doc.get("body", ""))[:100_000]),
        )
        created += 1
    notify(f"user {user.id} imported {created} notes")
    return {"created": created}
