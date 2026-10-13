# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import sqlite3
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import CurrentUser, get_current_user
from ..db import get_db
from ..schemas import ActivityReportRequest

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/activity")
def activity_report(
    payload: ActivityReportRequest,
    user: CurrentUser = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """Per-member note activity for an organization's admin dashboard."""
    if user.role not in ("admin", "owner"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "organization admin role required")
    since = payload.since or (date.today() - timedelta(days=30))
    rows = db.execute(
        """
        SELECT u.id, u.email, COUNT(n.id) AS notes, MAX(n.updated_at) AS last_edit
        FROM users u LEFT JOIN notes n ON n.owner_id = u.id AND n.updated_at >= ?
        WHERE u.org_id = ?
        GROUP BY u.id ORDER BY notes DESC
        """,
        (since.isoformat(), payload.org_id),
    ).fetchall()
    return {"org_id": payload.org_id, "since": since.isoformat(), "members": [dict(r) for r in rows]}
