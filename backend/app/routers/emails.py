"""Email ingestion and retrieval endpoints.

POST /api/emails/analyze  — upload a .eml file for parsing + storage
GET  /api/emails          — list analyzed emails
GET  /api/emails/{id}     — retrieve a single email with full detail
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Attachment as AttachmentModel
from ..models import Email, EmailHeader
from ..parsers.mime_parser import parse_email
from ..schemas.email import EmailDetail, EmailSummary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["emails"])

# Allowed MIME types for upload validation
_ALLOWED_CONTENT_TYPES = {
    "message/rfc822",
    "application/octet-stream",  # browsers sometimes send .eml as this
    "text/plain",
}

_MAX_FILENAME_LEN = 512


def _validate_upload(file: UploadFile) -> None:
    """Reject oversized or non-.eml uploads early."""
    if file.size is not None and file.size > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {settings.max_upload_size_mb} MB limit.",
        )

    # Check filename extension — hostile input may have any Content-Type
    filename = (file.filename or "").lower()
    if not filename.endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted.",
        )


def _persist_parsed(
    db: Session,
    parsed,
    filename: str | None,
) -> Email:
    """Write the parsed email and its children to the database.

    The evidence SHA-256 was already computed by the parser on the raw bytes.
    """
    email_record = Email(
        sha256=parsed.raw_sha256,
        filename=filename,
        size=parsed.raw_size,
        subject=parsed.subject,
        sender=parsed.sender,
        sender_name=parsed.sender_name,
        reply_to=parsed.reply_to,
        to=parsed.to,
        cc=parsed.cc,
        message_id=parsed.message_id,
        date=parsed.date,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )
    db.add(email_record)
    db.flush()  # get the auto-generated id

    # Persist every header in original order
    for h in parsed.headers:
        db.add(
            EmailHeader(
                email_id=email_record.id,
                name=h.name,
                value=h.value,
                position=h.position,
            )
        )

    # Persist attachment metadata (content stays inert in the DB)
    for att in parsed.attachments:
        db.add(
            AttachmentModel(
                email_id=email_record.id,
                filename=att.filename,
                content_type=att.content_type,
                size=att.size,
                sha256=att.sha256,
                content=att.content,
            )
        )

    db.commit()
    db.refresh(email_record)
    return email_record


# ── Endpoints ───────────────────────────────────────────────────────


@router.post("/analyze", response_model=EmailDetail, status_code=201)
async def analyze_email(
    file: Annotated[UploadFile, File(description=".eml file to analyze")],
    db: Annotated[Session, Depends(get_db)],
):
    """Upload and analyze a single .eml file.

    1. Validate upload (extension, size)
    2. Read raw bytes
    3. Compute SHA-256 evidence hash on raw bytes BEFORE parsing
    4. Parse MIME: extract headers, body, attachments
    5. Persist to database
    6. Return structured analysis response
    """
    _validate_upload(file)

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    parsed = parse_email(raw_bytes)
    record = _persist_parsed(db, parsed, file.filename)

    logger.info(
        "Email ingested: id=%d sha256=%s…", record.id, record.sha256[:12]
    )
    return record


@router.get("", response_model=list[EmailSummary])
def list_emails(
    db: Annotated[Session, Depends(get_db)],
    skip: int = 0,
    limit: int = 50,
):
    """List analyzed emails (newest first)."""
    emails = (
        db.query(Email)
        .order_by(Email.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return emails


@router.get("/{email_id}", response_model=EmailDetail)
def get_email(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Retrieve a single email with all headers and attachments."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    return email_record
