"""API response schemas.

These mirror the SQLAlchemy models (from_attributes) so the JSON contract
stays stable even if the ORM layer changes.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HeaderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    value: str
    position: int


class AttachmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str | None = None
    content_type: str
    size: int
    sha256: str


class Recipient(BaseModel):
    name: str | None = None
    address: str | None = None


class EmailSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int | None = None
    sha256: str
    filename: str | None = None
    size: int
    subject: str | None = None
    sender: str | None = None
    sender_name: str | None = None
    date: datetime | None = None
    created_at: datetime


class AuthResultOut(BaseModel):
    """One SPF / DKIM / DMARC authentication check result."""
    model_config = ConfigDict(from_attributes=True)

    mechanism: str  # SPF | DKIM | DMARC
    result: str  # PASS | FAIL | SOFTFAIL | NONE | ...
    domain: str | None = None
    selector: str | None = None
    aligned: bool | None = None
    source: str  # header_claim | independent_check
    details: str | None = None
    checked_at: datetime


class AuthenticationSummary(BaseModel):
    """Aggregated authentication results for an email."""
    spf: AuthResultOut | None = None
    dkim: AuthResultOut | None = None
    dmarc: AuthResultOut | None = None
    all_results: list[AuthResultOut] = Field(default_factory=list)


class EmailDetail(EmailSummary):
    reply_to: str | None = None
    to: list[Recipient] = Field(default_factory=list)
    cc: list[Recipient] = Field(default_factory=list)
    message_id: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    headers: list[HeaderOut] = Field(default_factory=list)
    attachments: list[AttachmentOut] = Field(default_factory=list)
    authentication: AuthenticationSummary | None = None
