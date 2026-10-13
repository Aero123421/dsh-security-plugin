# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import CurrentUser, get_current_user
from ..db import get_db
from ..schemas import NoteIn, NoteOut

router = APIRouter(prefix="/notes", tags=["notes"])

NOTE_COLUMNS = "id, owner_id, title, body, updated_at"


@router.get("", response_model=list[NoteOut])
def list_notes(
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    rows = db.execute(f"SELECT {NOTE_COLUMNS} FROM notes WHERE owner_id = ? ORDER BY updated_at DESC", (user.id,))
    return [dict(row) for row in rows]


@router.get("/search", response_model=list[NoteOut])
def search_notes(
    q: str = Query(min_length=1, max_length=100),
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    sql = f"SELECT {NOTE_COLUMNS} FROM notes WHERE owner_id = {user.id} AND (title LIKE '%{q}%' OR body LIKE '%{q}%')"
    rows = db.execute(sql).fetchall()
    return [dict(row) for row in rows]


@router.get("/{note_id}", response_model=NoteOut)
def get_note(
    note_id: int,
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    note = db.execute("SELECT id, owner_id, title, body, updated_at FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")
    return dict(note)


@router.put("/{note_id}", response_model=NoteOut)
def update_note(
    note_id: int,
    payload: NoteIn,
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    note = db.execute("SELECT id, owner_id FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None or note["owner_id"] != user.id:
        # Same response as a missing note, so ids of other users' notes are not confirmed.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")
    db.execute(
        "UPDATE notes SET title = ?, body = ?, updated_at = datetime('now') WHERE id = ?",
        (payload.title, payload.body, note_id),
    )
    return dict(db.execute(f"SELECT {NOTE_COLUMNS} FROM notes WHERE id = ?", (note_id,)).fetchone())


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: int,
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    cursor = db.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, user.id))
    if cursor.rowcount == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")
