# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import base64
import pickle

from fastapi import APIRouter, Cookie, Depends, Response

from ..auth import CurrentUser, get_current_user
from ..schemas import Preferences

router = APIRouter(prefix="/preferences", tags=["preferences"])

COOKIE_NAME = "notes_prefs"
DEFAULTS = Preferences()


@router.get("", response_model=Preferences)
def read_preferences(
    notes_prefs: str | None = Cookie(default=None),
    user: CurrentUser = Depends(get_current_user),
):
    if not notes_prefs:
        return DEFAULTS
    try:
        prefs = pickle.loads(base64.b64decode(notes_prefs))
    except Exception:
        return DEFAULTS
    return Preferences(**prefs) if isinstance(prefs, dict) else DEFAULTS


@router.put("", response_model=Preferences)
def save_preferences(
    prefs: Preferences,
    response: Response,
    user: CurrentUser = Depends(get_current_user),
):
    blob = base64.b64encode(pickle.dumps(prefs.model_dump())).decode()
    response.set_cookie(COOKIE_NAME, blob, max_age=60 * 60 * 24 * 365, secure=True, httponly=True, samesite="lax")
    return prefs
