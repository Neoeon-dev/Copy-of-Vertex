"""
Safe Text & Content Normalization Utilities for VERTEX.
Processes email text, strips HTML safely, handles malformed Unicode,
sanitizes NUL bytes, extracts URLs for metadata only (zero network calls),
and inspects attachments inertly without executing.
"""
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional, Tuple
import hashlib
import os
import re
import unicodedata


class InertHTMLTextExtractor(HTMLParser):
    """
    Standard-library HTML parser that extracts text and link targets
    without executing JavaScript, CSS, or external resources.
    """
    def __init__(self):
        super().__init__()
        self.text_parts: List[str] = []
        self.links: List[str] = []
        self.in_ignored_tag = False
        self.ignored_tags = {"script", "style", "head", "title", "meta", "link"}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        if tag_lower in self.ignored_tags:
            self.in_ignored_tag = True
        elif tag_lower == "a":
            for attr, val in attrs:
                if attr.lower() == "href" and val:
                    self.links.append(val.strip())

    def handle_endtag(self, tag: str):
        if tag.lower() in self.ignored_tags:
            self.in_ignored_tag = False

    def handle_data(self, data: str):
        if not self.in_ignored_tag and data:
            self.text_parts.append(data)

    def get_text(self) -> str:
        return " ".join(self.text_parts).strip()

    def get_links(self) -> List[str]:
        return self.links


# Safe URL regex matching common schemes
URL_REGEX = re.compile(
    r'(?:https?|ftp)://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*',
    re.IGNORECASE
)


def sanitize_null_bytes(text: Optional[str]) -> str:
    """Replaces NUL bytes (\x00) with Unicode replacement character (\ufffd)."""
    if text is None:
        return ""
    return text.replace("\x00", "\ufffd")


def normalize_unicode(text: Optional[str]) -> str:
    """Normalizes Unicode characters to NFKC form and handles common homoglyphs/controls."""
    if text is None:
        return ""
    # Strip dangerous zero-width and bidirectional override control characters
    # U+200B (Zero-width space), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM),
    # U+202A to U+202E (Bidi embedding/overrides)
    sanitized = re.sub(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e]", "", text)
    sanitized = unicodedata.normalize("NFKC", sanitized)
    return sanitize_null_bytes(sanitized)


def strip_html_safely(html_content: str) -> Tuple[str, List[str]]:
    """
    Safely strips HTML tags returning clean plain text and extracted link URLs.
    Never executes scripts or makes network requests.
    """
    if not html_content:
        return ("", [])
    extractor = InertHTMLTextExtractor()
    try:
        extractor.feed(html_content)
        plain = extractor.get_text()
        links = extractor.get_links()
    except Exception:
        # Fallback to regex tag stripping on malformed HTML
        plain = re.sub(r"<[^>]+>", " ", html_content)
        links = []
    return (plain, links)


def extract_urls_safely(text: str) -> List[str]:
    """
    Extracts all URLs from text or HTML via regex.
    STRICT SECURITY RULE: Never visits, resolves, or queries the extracted URLs.
    """
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for u in matches:
        u_clean = u.rstrip(".,;!?:\"')]>")
        if u_clean and u_clean not in seen:
            seen.add(u_clean)
            unique_urls.append(u_clean)
    return unique_urls


def extract_attachment_metadata_inert(
    filename: Optional[str],
    content_type: Optional[str],
    raw_payload: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Extracts inert metadata from an attachment without executing or parsing payload.
    """
    safe_name = sanitize_null_bytes(filename or "unnamed_attachment")
    # Clean filename of path traversal characters
    safe_name = os.path.basename(safe_name.replace("\\", "/"))
    ext = os.path.splitext(safe_name)[1].lower()
    
    size = len(raw_payload) if raw_payload else 0
    sha256 = hashlib.sha256(raw_payload).hexdigest() if raw_payload else None

    return {
        "filename": safe_name,
        "extension": ext,
        "content_type": content_type or "application/octet-stream",
        "size_bytes": size,
        "sha256": sha256,
        "is_executable": ext in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".pif", ".com"},
        "is_archive": ext in {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".iso"},
        "is_macro_enabled": ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"},
    }


def normalize_email_body_and_subject(
    subject: Optional[str],
    body: Optional[str],
    is_html: bool = False,
) -> Tuple[str, str, List[str]]:
    """
    Comprehensive normalization:
    - Normalizes Unicode and sanitizes NUL bytes.
    - Strips HTML safely if present.
    - Extracts URLs safely for metadata.
    Returns (clean_subject, clean_body, extracted_urls).
    """
    clean_sub = normalize_unicode(subject or "").strip()
    raw_b = body or ""
    
    urls: List[str] = []
    if is_html or ("<html" in raw_b.lower() or "<body" in raw_b.lower() or "<div" in raw_b.lower()):
        plain_body, html_urls = strip_html_safely(raw_b)
        text_urls = extract_urls_safely(plain_body)
        urls = list(dict.fromkeys(html_urls + text_urls))
        clean_body = plain_body
    else:
        clean_body = raw_b
        urls = extract_urls_safely(raw_b)

    clean_body = normalize_unicode(clean_body)
    clean_body = re.sub(r"[ \t]+", " ", clean_body)
    clean_body = re.sub(r"\n{3,}", "\n\n", clean_body).strip()

    return (clean_sub, clean_body, urls)
