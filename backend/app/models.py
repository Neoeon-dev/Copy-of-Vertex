"""SQLAlchemy models for the forensic evidence store.

Relationship notes
------------------
* ``Email`` is the root evidence record. ``sha256`` is computed over the exact
  raw uploaded bytes BEFORE any parsing, so it never depends on how we
  (re)serialize the message.
* ``EmailHeader`` stores EVERY header, preserving original order via
  ``position``. Multiple ``Received`` headers are kept as separate rows.
* ``Attachment`` stores attachment bytes inertly (never executed, never
  rendered). The bytes are stored so analysts can download them later; only
  metadata is returned by the JSON API.
"""
from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, DateTime, ForeignKey, LargeBinary,
                        String, Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Case(Base):
    """A forensic investigation case. Case management arrives on a later
    milestone; the table exists now so emails can already reference a case."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    emails: Mapped[list["Email"]] = relationship(back_populates="case")


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(
        ForeignKey("cases.id"), nullable=True, index=True
    )

    # Evidence identity: SHA-256 of the exact uploaded bytes.
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    size: Mapped[int] = mapped_column(BigInteger)

    # Parsed metadata (nullable because hostile/malformed input is common).
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sender_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reply_to: Mapped[str | None] = mapped_column(String(512), nullable=True)
    to: Mapped[list | None] = mapped_column(JSON, nullable=True)
    cc: Mapped[list | None] = mapped_column(JSON, nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    case: Mapped[Case | None] = relationship(back_populates="emails")
    headers: Mapped[list["EmailHeader"]] = relationship(
        back_populates="email",
        cascade="all, delete-orphan",
        order_by="EmailHeader.position",
    )
    attachments: Mapped[list["Attachment"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    authentication_results: Mapped[list["EmailAuthenticationResult"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Email id={self.id} sha256={self.sha256[:12]}…>"


class EmailHeader(Base):
    """One raw header line. Every header is retained, in original order."""

    __tablename__ = "email_headers"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[int] = mapped_column(
        ForeignKey("emails.id"), index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    value: Mapped[str] = mapped_column(Text)
    position: Mapped[int] = mapped_column()

    email: Mapped[Email] = relationship(back_populates="headers")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id"), index=True)
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str] = mapped_column(String(256))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    # Inert captured bytes; never executed or rendered by the backend.
    content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    email: Mapped[Email] = relationship(back_populates="attachments")


class EmailAuthenticationResult(Base):
    """Stores SPF / DKIM / DMARC analysis results for an email.

    Each row represents one authentication mechanism check.  The ``source``
    column distinguishes between:

    * ``header_claim`` — result reported in Authentication-Results header
    * ``independent_check`` — verified by our own DNS / crypto analysis
    """

    __tablename__ = "email_authentication_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[int] = mapped_column(
        ForeignKey("emails.id"), index=True
    )
    mechanism: Mapped[str] = mapped_column(
        String(32)
    )  # SPF | DKIM | DMARC
    result: Mapped[str] = mapped_column(
        String(32)
    )  # PASS | FAIL | SOFTFAIL | NONE | ...
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    selector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    aligned: Mapped[bool | None] = mapped_column(nullable=True)
    source: Mapped[str] = mapped_column(
        String(32)
    )  # header_claim | independent_check
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    email: Mapped[Email] = relationship(
        back_populates="authentication_results"
    )


class AuditLog(Base):
    """Append-only audit log. Records every important action on the system.

    Each entry is immutable — never updated or deleted.
    The hash_chain field implements an append-only hash chain:
      current_hash = SHA256(record_json + previous_hash)
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    action: Mapped[str] = mapped_column(String(64))  # e.g. email.uploaded, case.created
    entity_type: Mapped[str] = mapped_column(String(32))  # email | case | analysis
    entity_id: Mapped[int | None] = mapped_column(nullable=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64))


class EvidenceChain(Base):
    """Evidence hash chain entry.

    Each email analysis event creates an entry. The chain ensures
    tamper-evidence: modifying any record breaks the chain.
    """

    __tablename__ = "evidence_chain"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[int] = mapped_column(
        ForeignKey("emails.id"), index=True
    )
    evidence_id: Mapped[str] = mapped_column(String(64), index=True)  # SHA-256 of raw email
    action: Mapped[str] = mapped_column(String(64))  # uploaded | analyzed | exported
    content_hash: Mapped[str] = mapped_column(String(64))  # hash of the action data
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[str] = mapped_column(String(64))  # chain integrity hash
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    details: Mapped[str | None] = mapped_column(Text, nullable=True)