"""Attachment analysis module.

Analyzes email attachments WITHOUT executing them:
- Filename and extension analysis
- MIME type validation
- Double extension detection
- Suspicious extension detection
- Size analysis
- SHA-256 hash

NEVER executes, renders, or opens attachments.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Executable extensions that are inherently suspicious in email attachments
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "msi", "msp", "mst", "cpl", "hta", "inf",
    "reg", "rgs", "sct", "shb", "shs", "lnk", "app", "jar", "class",
    "workflow", "command", "csh", "ksh", "bash", "zsh", "fish",
}

# Archive extensions that could contain malicious payloads
ARCHIVE_EXTENSIONS = {
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab",
}

# Document extensions that can contain macros
DOCUMENT_EXTENSIONS = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
    "rtf", "pub", "pdf", "jpg", "jpeg", "png", "gif", "bmp",
}

# MIME type to extension mapping (common mismatches)
MIME_EXTENSION_MAP = {
    "application/x-msdownload": ["exe", "dll", "scr"],
    "application/x-executable": ["exe", "elf"],
    "application/x-bat": ["bat"],
    "application/x-vbs": ["vbs"],
    "application/javascript": ["js"],
    "text/x-script": ["vbs", "js"],
}


@dataclass
class AttachmentAnalysis:
    """Analysis result for a single attachment."""

    filename: str | None = None
    content_type: str | None = None
    size: int = 0
    sha256: str = ""
    extension: str | None = None
    is_dangerous_extension: bool = False
    is_archive: bool = False
    has_double_extension: bool = False
    has_suspicious_extension: bool = False
    mime_mismatch: bool = False
    warnings: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
            "is_dangerous_extension": self.is_dangerous_extension,
            "is_archive": self.is_archive,
            "has_double_extension": self.has_double_extension,
            "has_suspicious_extension": self.has_suspicious_extension,
            "mime_mismatch": self.mime_mismatch,
            "warnings": self.warnings,
            "risk_score": self.risk_score,
        }


def _get_extension(filename: str | None) -> str | None:
    """Extract the file extension (without dot)."""
    if not filename:
        return None
    _, ext = os.path.splitext(filename)
    return ext.lstrip(".").lower() if ext else None


def _check_double_extension(filename: str | None) -> bool:
    """Check for double extensions like document.pdf.exe."""
    if not filename:
        return False
    parts = filename.split(".")
    if len(parts) >= 3:
        # Check if the last extension is dangerous but there's a document extension before it
        last_ext = parts[-1].lower()
        second_ext = parts[-2].lower()
        if last_ext in DANGEROUS_EXTENSIONS and second_ext in DOCUMENT_EXTENSIONS:
            return True
        # Also check for common tricks: file.pdf.scr
        if last_ext in DANGEROUS_EXTENSIONS and second_ext in ARCHIVE_EXTENSIONS:
            return True
    return False


def _check_mime_mismatch(content_type: str | None, extension: str | None) -> bool:
    """Check if MIME type matches the file extension."""
    if not content_type or not extension:
        return False

    ct_lower = content_type.lower().split(";")[0].strip()

    # Check if the extension is in the list of expected extensions for this MIME type
    expected_extensions = MIME_EXTENSION_MAP.get(ct_lower, [])
    if expected_extensions and extension not in expected_extensions:
        return True

    return False


def analyze_attachment(
    filename: str | None,
    content_type: str,
    size: int,
    sha256: str,
    content: bytes | None = None,
) -> AttachmentAnalysis:
    """Analyze a single email attachment.

    Args:
        filename: Original filename
        content_type: MIME content type
        size: Size in bytes
        sha256: SHA-256 hash of the content
        content: Raw bytes (optional, for additional analysis)
    """
    analysis = AttachmentAnalysis(
        filename=filename,
        content_type=content_type,
        size=size,
        sha256=sha256,
    )

    extension = _get_extension(filename)
    analysis.extension = extension

    # Dangerous extension check
    if extension and extension in DANGEROUS_EXTENSIONS:
        analysis.is_dangerous_extension = True
        analysis.warnings.append(f"Dangerous file extension: .{extension}")

    # Archive check
    if extension and extension in ARCHIVE_EXTENSIONS:
        analysis.is_archive = True
        analysis.warnings.append(f"Archive attachment: .{extension}")

    # Double extension check
    if _check_double_extension(filename):
        analysis.has_double_extension = True
        analysis.warnings.append(f"Double extension detected: {filename}")

    # Suspicious extension (executable or archive)
    if analysis.is_dangerous_extension or analysis.has_double_extension:
        analysis.has_suspicious_extension = True

    # MIME type mismatch
    if _check_mime_mismatch(content_type, extension):
        analysis.mime_mismatch = True
        analysis.warnings.append(
            f"MIME type mismatch: {content_type} vs .{extension}"
        )

    # Size analysis
    if size == 0:
        analysis.warnings.append("Empty attachment (0 bytes)")
    elif size > 10 * 1024 * 1024:  # > 10MB
        analysis.warnings.append(f"Large attachment: {size / (1024 * 1024):.1f} MB")

    # Compute risk score
    risk = 0.0
    if analysis.is_dangerous_extension:
        risk += 0.5
    if analysis.has_double_extension:
        risk += 0.4
    if analysis.mime_mismatch:
        risk += 0.2
    if analysis.is_archive:
        risk += 0.1
    if size > 10 * 1024 * 1024:
        risk += 0.05
    analysis.risk_score = min(1.0, risk)

    return analysis


def analyze_attachments(
    attachments: list[dict[str, Any]],
) -> list[AttachmentAnalysis]:
    """Analyze a list of attachment dicts (from the parser output)."""
    results: list[AttachmentAnalysis] = []
    for att in attachments:
        results.append(analyze_attachment(
            filename=att.get("filename"),
            content_type=att.get("content_type", "application/octet-stream"),
            size=att.get("size", 0),
            sha256=att.get("sha256", ""),
            content=att.get("content"),
        ))
    return results
