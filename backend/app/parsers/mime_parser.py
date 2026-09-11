"""MIME / RFC-822 email parser.

Parses raw .eml bytes and extracts:
- All headers (preserving original order)
- Sender, Reply-To, To, CC, Subject, Date, Message-ID
- Body (plain text and HTML)
- Attachments (metadata + inert bytes)

Every uploaded email is treated as hostile input.
The parser must handle malformed MIME gracefully.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import logging
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ParsedAttachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str
    content: bytes  # inert — never executed


@dataclass
class ParsedHeader:
    name: str
    value: str
    position: int


@dataclass
class ParsedEmail:
    """Structured output from parsing a single .eml file."""

    # Raw evidence
    raw_sha256: str  # SHA-256 of the exact uploaded bytes
    raw_size: int

    # Extracted metadata
    subject: str | None = None
    sender: str | None = None  # email address only
    sender_name: str | None = None  # display name
    reply_to: str | None = None
    to: list[dict[str, str | None]] = field(default_factory=list)
    cc: list[dict[str, str | None]] = field(default_factory=list)
    message_id: str | None = None
    date: Any = None  # datetime or None

    # Body
    body_text: str | None = None
    body_html: str | None = None

    # Headers — every single one, in original order
    headers: list[ParsedHeader] = field(default_factory=list)

    # Attachments
    attachments: list[ParsedAttachment] = field(default_factory=list)


def _decode_header_value(raw_value: str) -> str:
    """Decode an RFC-2047 encoded header value to a plain string."""
    if raw_value is None:
        return ""
    # email.header.decode_header returns list of (bytes, charset) or (str, None)
    from email.header import decode_header

    parts = decode_header(raw_value)
    decoded_parts: list[str] = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded_parts.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            decoded_parts.append(str(data))
    return "".join(decoded_parts)


def _parse_recipients(value: str | None) -> list[dict[str, str | None]]:
    """Parse a To/CC header into a list of {name, address} dicts."""
    if not value:
        return []
    from email.utils import getaddresses

    pairs = getaddresses([value])
    return [{"name": name or None, "address": addr or None} for name, addr in pairs]


def _extract_sender_info(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Return (email_address, display_name) from the From header."""
    raw_from = msg.get("From", "")
    from email.utils import parseaddr

    # parseaddr returns (display_name, email_address)
    name, addr = parseaddr(raw_from)
    return (addr or None, name or None)


def _extract_body(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Walk the message and extract plain-text and HTML bodies."""
    body_text: str | None = None
    body_html: str | None = None

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            # Skip attachments
            if "attachment" in disp:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if ct == "text/plain" and body_text is None:
                body_text = text
            elif ct == "text/html" and body_html is None:
                body_html = text
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if ct == "text/plain":
                body_text = text
            elif ct == "text/html":
                body_html = text

    return body_text, body_html


def _extract_attachments(msg: EmailMessage) -> list[ParsedAttachment]:
    """Walk the message and extract attachment metadata + inert bytes."""
    attachments: list[ParsedAttachment] = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" not in disp:
            continue

        filename = part.get_filename() or None
        if filename:
            from email.header import decode_header

            parts = decode_header(filename)
            decoded: list[str] = []
            for data, charset in parts:
                if isinstance(data, bytes):
                    decoded.append(data.decode(charset or "utf-8", errors="replace"))
                else:
                    decoded.append(str(data))
            filename = "".join(decoded)

        content_type = part.get_content_type() or "application/octet-stream"
        payload = part.get_payload(decode=True) or b""
        sha256 = hashlib.sha256(payload).hexdigest()

        attachments.append(
            ParsedAttachment(
                filename=filename,
                content_type=content_type,
                size=len(payload),
                sha256=sha256,
                content=payload,
            )
        )

    return attachments


def _extract_all_headers(msg: EmailMessage) -> list[ParsedHeader]:
    """Extract ALL headers preserving original order.

    Uses ``email.message.Message.items()`` which yields headers in the
    order they appear in the raw message.
    """
    headers: list[ParsedHeader] = []
    for position, (name, value) in enumerate(msg.items()):
        headers.append(
            ParsedHeader(
                name=name,
                value=value or "",
                position=position,
            )
        )
    return headers


def _parse_date(date_str: str | None) -> Any:
    """Parse an email Date header into a datetime, or None."""
    if not date_str:
        return None
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(date_str)
    except (ValueError, TypeError):
        logger.warning("Failed to parse date header: %s", date_str)
        return None


def parse_email(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail.

    The evidence hash (raw_sha256) is computed over the exact input bytes
    before any transformation.
    """
    # --- Evidence hash: computed on raw uploaded bytes, BEFORE parsing ---
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # Parse with the stdlib email parser using a strict-ish policy
    msg: EmailMessage = message_from_bytes(
        raw_bytes, policy=email.policy.default
    )

    # Metadata
    sender_addr, sender_name = _extract_sender_info(msg)
    date_value = _parse_date(msg.get("Date"))
    body_text, body_html = _extract_body(msg)
    attachments = _extract_attachments(msg)
    headers = _extract_all_headers(msg)

    parsed = ParsedEmail(
        raw_sha256=raw_sha256,
        raw_size=len(raw_bytes),
        subject=_decode_header_value(msg.get("Subject") or ""),
        sender=sender_addr,
        sender_name=sender_name or None,
        reply_to=msg.get("Reply-To"),
        to=_parse_recipients(msg.get("To")),
        cc=_parse_recipients(msg.get("Cc")),
        message_id=msg.get("Message-ID"),
        date=date_value,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        attachments=attachments,
    )

    logger.info(
        "Parsed email: subject=%r sender=%r headers=%d attachments=%d",
        parsed.subject,
        parsed.sender,
        len(parsed.headers),
        len(parsed.attachments),
    )

    return parsed
