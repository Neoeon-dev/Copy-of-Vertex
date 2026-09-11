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
    if not raw_value:
        return ""
    try:
        from email.header import decode_header

        parts = decode_header(raw_value)
        decoded_parts: list[str] = []
        for data, charset in parts:
            if isinstance(data, bytes):
                decoded_parts.append(data.decode(charset or "utf-8", errors="replace"))
            else:
                decoded_parts.append(str(data))
        return "".join(decoded_parts)
    except Exception as e:
        logger.warning("Failed to decode header value %r: %s", raw_value, e)
        return str(raw_value)


def _safe_header_value(value: Any) -> str:
    """Safely convert header value to string, decoding RFC-2047 if needed."""
    if value is None:
        return ""
    try:
        val_str = str(value)
        if "=?" in val_str and "?=" in val_str:
            val_str = _decode_header_value(val_str)
        return val_str.replace("\x00", "\ufffd")
    except Exception as e:
        logger.warning("Error converting header value %r: %s", value, e)
        return ""


def _sanitize_for_db(val: str | None) -> str | None:
    """Sanitize string fields by replacing NUL bytes with unicode replacement characters."""
    if val is None:
        return None
    return val.replace("\x00", "\ufffd")


def _parse_recipients(value: str | None) -> list[dict[str, str | None]]:
    """Parse a To/CC header into a list of {name, address} dicts."""
    if not value:
        return []
    try:
        from email.utils import getaddresses

        pairs = getaddresses([value])
        return [{"name": name or None, "address": addr or None} for name, addr in pairs]
    except Exception as e:
        logger.warning("Failed to parse recipient addresses from %r: %s", value, e)
        return []


def _extract_sender_info(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Return (email_address, display_name) from the From header."""
    try:
        raw_from = _safe_header_value(msg.get("From", ""))
        if not raw_from:
            return (None, None)
        from email.utils import parseaddr

        name, addr = parseaddr(raw_from)
        return (addr or None, name or None)
    except Exception as e:
        logger.warning("Failed to extract sender info: %s", e)
        return (None, None)


def _extract_body(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Extract plain-text and HTML bodies for the primary email.

    Traverses the MIME tree without descending into attachments or nested
    message/rfc822 subparts.
    """
    body_text: str | None = None
    body_html: str | None = None

    def _walk_body(part: EmailMessage) -> None:
        nonlocal body_text, body_html
        if part is not msg:
            disp = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp or part.get_content_type() == "message/rfc822":
                return

        if part.is_multipart():
            try:
                subparts = list(part.iter_parts())
            except Exception:
                payload = part.get_payload()
                subparts = payload if isinstance(payload, list) else []
            for subpart in subparts:
                _walk_body(subpart)
        else:
            ct = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception as e:
                logger.warning("Failed to decode part payload: %s", e)
                payload = None

            if payload is not None:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="replace")
                except Exception:
                    text = payload.decode("utf-8", errors="replace")
                if ct == "text/plain" and body_text is None:
                    body_text = text
                elif ct == "text/html" and body_html is None:
                    body_html = text

    _walk_body(msg)
    return body_text, body_html


def _extract_attachments(msg: EmailMessage) -> list[ParsedAttachment]:
    """Walk the message and extract attachment metadata + inert bytes.

    Captures:
    - Standard attachments with Content-Disposition: attachment or filename
    - Encapsulated message/rfc822 emails as .eml attachments
    """
    attachments: list[ParsedAttachment] = []

    for part in msg.walk():
        if part is msg:
            continue

        ct = part.get_content_type()
        disp = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename() or part.get_param("name")

        if filename:
            try:
                from email.header import decode_header

                parts = decode_header(filename)
                decoded: list[str] = []
                for data, charset in parts:
                    if isinstance(data, bytes):
                        decoded.append(data.decode(charset or "utf-8", errors="replace"))
                    else:
                        decoded.append(str(data))
                filename = "".join(decoded)
            except Exception as e:
                logger.warning("Failed to decode attachment filename %r: %s", filename, e)

        # 1. Encapsulated message/rfc822 (.eml)
        if ct == "message/rfc822":
            if not filename:
                filename = "attached_message.eml"
            elif not filename.lower().endswith(".eml"):
                filename = f"{filename}.eml"

            sub_payload = part.get_payload()
            try:
                if isinstance(sub_payload, list) and len(sub_payload) > 0:
                    first_child = sub_payload[0]
                    if hasattr(first_child, "as_bytes"):
                        payload_bytes = first_child.as_bytes()
                    elif isinstance(first_child, bytes):
                        payload_bytes = first_child
                    else:
                        payload_bytes = str(first_child).encode("utf-8", errors="replace")
                elif hasattr(sub_payload, "as_bytes"):
                    payload_bytes = sub_payload.as_bytes()
                elif isinstance(sub_payload, bytes):
                    payload_bytes = sub_payload
                else:
                    payload_bytes = part.as_bytes()
            except Exception as e:
                logger.warning("Failed to extract message/rfc822 payload bytes: %s", e)
                payload_bytes = b""

            sha256 = hashlib.sha256(payload_bytes).hexdigest()
            attachments.append(
                ParsedAttachment(
                    filename=filename,
                    content_type="message/rfc822",
                    size=len(payload_bytes),
                    sha256=sha256,
                    content=payload_bytes,
                )
            )
            continue

        # Skip multipart containers
        if part.get_content_maintype() == "multipart":
            continue

        # 2. Standard attachments
        is_attachment = ("attachment" in disp) or (filename is not None)
        if not is_attachment:
            continue

        content_type = ct or "application/octet-stream"
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as e:
            logger.warning("Failed to decode attachment payload: %s", e)
            payload = b""

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
    order they appear in the raw message. Preserves custom, RFC, and
    unknown headers.
    """
    headers: list[ParsedHeader] = []
    try:
        items = list(msg.items())
    except Exception as e:
        logger.warning("Failed to iterate message items: %s", e)
        return headers

    for position, (name, value) in enumerate(items):
        safe_val = _safe_header_value(value)
        headers.append(
            ParsedHeader(
                name=str(name),
                value=safe_val,
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
    try:
        msg: EmailMessage = message_from_bytes(
            raw_bytes, policy=email.policy.default
        )
    except Exception as e:
        logger.warning("Default policy parsing failed, falling back to compat32: %s", e)
        try:
            msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as e2:
            logger.error("All email parsing failed: %s", e2)
            return ParsedEmail(
                raw_sha256=raw_sha256,
                raw_size=len(raw_bytes),
                subject="(Unparseable Email)",
            )

    # Metadata
    sender_addr, sender_name = _extract_sender_info(msg)
    date_value = _parse_date(_safe_header_value(msg.get("Date")))
    body_text, body_html = _extract_body(msg)
    attachments = _extract_attachments(msg)
    headers = _extract_all_headers(msg)

    raw_subject = msg.get("Subject")
    subject_str = _decode_header_value(str(raw_subject)) if raw_subject is not None else ""

    parsed = ParsedEmail(
        raw_sha256=raw_sha256,
        raw_size=len(raw_bytes),
        subject=_sanitize_for_db(subject_str) or "",
        sender=_sanitize_for_db(sender_addr),
        sender_name=_sanitize_for_db(sender_name) or None,
        reply_to=_safe_header_value(msg.get("Reply-To")) or None,
        to=_parse_recipients(_safe_header_value(msg.get("To"))),
        cc=_parse_recipients(_safe_header_value(msg.get("Cc"))),
        message_id=_safe_header_value(msg.get("Message-ID")) or None,
        date=date_value,
        body_text=_sanitize_for_db(body_text),
        body_html=_sanitize_for_db(body_html),
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
