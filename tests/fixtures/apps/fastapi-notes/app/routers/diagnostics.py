# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import subprocess

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import CurrentUser, get_current_user
from ..config import REPO_DIR
from ..schemas import PingRequest

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])


def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role required")
    return user


@router.get("/version")
def deployed_version(user: CurrentUser = Depends(require_admin)):
    status_out = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_DIR, capture_output=True, text=True, timeout=5)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_DIR, capture_output=True, text=True, timeout=5)
    return {"commit": head.stdout.strip(), "dirty": bool(status_out.stdout.strip())}


@router.post("/ping")
def ping_host(payload: PingRequest, user: CurrentUser = Depends(get_current_user)):
    """Lets support staff and customers check that a mail or webhook host is reachable.

    Hosts are names like "mail.example.com" or addresses like "203.0.113.7".
    """
    host = payload.host.strip()
    result = subprocess.run(f"ping -c 1 -W 2 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return {"host": host, "reachable": result.returncode == 0, "output": result.stdout[-2000:]}
