# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
from datetime import date
from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=100_000)
    notebook_id: Optional[int] = None


class NoteOut(BaseModel):
    id: int
    owner_id: int
    title: str
    body: str
    updated_at: str


class PingRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)


class LinkPreviewRequest(BaseModel):
    url: str


class LinkPreview(BaseModel):
    url: str
    status: int
    title: Optional[str] = None
    description: Optional[str] = None


class ActivityReportRequest(BaseModel):
    org_id: int
    since: Optional[date] = None


class Preferences(BaseModel):
    theme: str = "light"
    page_size: int = Field(default=20, ge=5, le=100)
    sort: str = "updated"
