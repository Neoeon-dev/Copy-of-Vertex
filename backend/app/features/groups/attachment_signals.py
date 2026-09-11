"""
Feature Group 9: Attachment Static Risk & Payload Telemetry.
Safely extracts metadata, extension patterns, macro risks, and double-extension
anomalies from email attachments WITHOUT executing or opening files.
"""
from typing import Dict, Any, Tuple, Optional, List
import os

from app.parsers.mime_parser import ParsedEmail, ParsedAttachment
from app.forensics.attachment_analyzer import (
    DANGEROUS_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    _get_extension,
    _check_double_extension,
    _check_mime_mismatch,
)

SCRIPT_EXTENSIONS = {
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "bat", "cmd", "sh", "bash", "py", "pl",
}

MACRO_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "ppsm", "sldm",
}


def extract_attachment_signals(
    parsed: Optional[ParsedEmail] = None,
    attachments_list: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic attachment risk features from ParsedEmail or attachment metadata.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    atts: List[Dict[str, Any]] = []
    if parsed and parsed.attachments:
        for a in parsed.attachments:
            atts.append({
                "filename": a.filename,
                "content_type": a.content_type,
                "size": a.size,
            })
    elif attachments_list:
        atts = attachments_list

    if not atts:
        feats["att_total_count"] = 0.0
        feats["att_executable_count"] = 0.0
        feats["att_archive_count"] = 0.0
        feats["att_script_count"] = 0.0
        feats["att_macro_count"] = 0.0
        feats["att_double_extension_count"] = 0.0
        feats["att_mime_mismatch_count"] = 0.0
        feats["att_max_size_bytes"] = 0.0
        feats["att_rfc822_count"] = 0.0
        return feats, exps

    total_count = len(atts)
    executable_count = 0
    archive_count = 0
    script_count = 0
    macro_count = 0
    double_ext_count = 0
    mime_mismatch_count = 0
    rfc822_count = 0
    sizes = []

    for a in atts:
        fn = a.get("filename") or ""
        ct = a.get("content_type") or "application/octet-stream"
        sz = int(a.get("size") or 0)
        sizes.append(sz)

        ext = _get_extension(fn)

        if ext in DANGEROUS_EXTENSIONS:
            executable_count += 1
        if ext in ARCHIVE_EXTENSIONS:
            archive_count += 1
        if ext in SCRIPT_EXTENSIONS:
            script_count += 1
        if ext in MACRO_EXTENSIONS:
            macro_count += 1
        if _check_double_extension(fn):
            double_ext_count += 1
        if _check_mime_mismatch(ct, ext):
            mime_mismatch_count += 1
        if ct.lower().startswith("message/rfc822") or ext == "eml":
            rfc822_count += 1

    feats["att_total_count"] = float(total_count)
    feats["att_executable_count"] = float(executable_count)
    feats["att_archive_count"] = float(archive_count)
    feats["att_script_count"] = float(script_count)
    feats["att_macro_count"] = float(macro_count)
    feats["att_double_extension_count"] = float(double_ext_count)
    feats["att_mime_mismatch_count"] = float(mime_mismatch_count)
    feats["att_max_size_bytes"] = float(max(sizes)) if sizes else 0.0
    feats["att_rfc822_count"] = float(rfc822_count)

    return feats, exps
