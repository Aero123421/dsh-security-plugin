# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
import re
from html import unescape

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import CurrentUser, get_current_user
from ..config import LINK_PREVIEW_TIMEOUT
from ..schemas import LinkPreview, LinkPreviewRequest

router = APIRouter(prefix="/links", tags=["links"])

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
DESCRIPTION_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)', re.IGNORECASE)


@router.post("/preview", response_model=LinkPreview)
def link_preview(payload: LinkPreviewRequest, user: CurrentUser = Depends(get_current_user)):
    """Fetches a pasted URL so the editor can show a title card under the link."""
    url = payload.url
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "only http(s) links can be previewed")
    try:
        response = httpx.get(url, timeout=LINK_PREVIEW_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"could not fetch link: {exc}") from exc
    html = response.text[:200_000]
    title = TITLE_RE.search(html)
    description = DESCRIPTION_RE.search(html)
    return LinkPreview(
        url=str(response.url),
        status=response.status_code,
        title=unescape(title.group(1)).strip() if title else None,
        description=unescape(description.group(1)).strip() if description else None,
    )
