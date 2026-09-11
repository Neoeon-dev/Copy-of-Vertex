"""
Robust, deterministic email text preprocessing pipeline for Phase D3 Semantic NLP.
Preserves critical phishing and security cues while safely normalizing untrusted text.
"""
from __future__ import annotations

import html
import re
import unicodedata
from typing import Optional, Dict, Any

SEMANTIC_PREPROCESSING_VERSION = "1.0.0"

# Pre-compiled regular expressions for performance and safety
RE_HTML_SCRIPT = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
RE_HTML_STYLE = re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
RE_HTML_TAGS = re.compile(r"<[^>]+>")
RE_URL = re.compile(
    r"(?:https?://|www\.)[^\s<>'\"`\(\)]+",
    re.IGNORECASE,
)
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
RE_MONEY = re.compile(
    r"[$€£¥]\s*\d+(?:,\d{3})*(?:\.\d+)?|\b\d+(?:,\d{3})*(?:\.\d+)?\s*(?:USD|EUR|GBP|CAD|AUD)\b",
    re.IGNORECASE,
)
RE_PHONE = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
RE_MULTIPLE_SPACES = re.compile(r"[ \t]+")
RE_MULTIPLE_NEWLINES = re.compile(r"\n{3,}")


class EmailTextPreprocessor:
    """
    Deterministic email text normalizer.
    
    Transforms raw subject and body strings into standardized representations
    with controlled special tokens ([SUBJECT], [BODY], [URL], [EMAIL], [MONEY], [PHONE], [EMPTY]).
    """

    def __init__(
        self,
        url_mode: str = "replace",  # "replace" ([URL]), "strip", or "keep"
        strip_html: bool = True,
        normalize_whitespace: bool = True,
        replace_email: bool = True,
        replace_money: bool = True,
        replace_phone: bool = False,
        lowercase: bool = False,
        part_mode: str = "both",  # "both", "subject_only", or "body_only"
    ) -> None:
        self.url_mode = url_mode
        self.strip_html = strip_html
        self.normalize_whitespace = normalize_whitespace
        self.replace_email = replace_email
        self.replace_money = replace_money
        self.replace_phone = replace_phone
        self.lowercase = lowercase
        self.part_mode = part_mode
        self.version = SEMANTIC_PREPROCESSING_VERSION

    def clean_text(self, text: Optional[str]) -> str:
        """
        Cleans and normalizes a single text segment (subject or body).
        """
        if text is None or not isinstance(text, str):
            return ""

        # 1. Unicode NFKC Normalization
        text = unicodedata.normalize("NFKC", text)

        # 2. Control Characters: strip non-printable characters except standard whitespace
        text = "".join(ch for ch in text if ch in "\n\r\t" or unicodedata.category(ch)[0] != "C")

        # 3. HTML Normalization
        if self.strip_html:
            text = RE_HTML_SCRIPT.sub(" ", text)
            text = RE_HTML_STYLE.sub(" ", text)
            text = html.unescape(text)
            text = RE_HTML_TAGS.sub(" ", text)

        # 4. URL Normalization
        if self.url_mode == "replace":
            text = RE_URL.sub(" [URL] ", text)
        elif self.url_mode == "strip":
            text = RE_URL.sub(" ", text)

        # 5. Email Address Normalization
        if self.replace_email:
            text = RE_EMAIL.sub(" [EMAIL] ", text)

        # 6. Currency / Money Normalization
        if self.replace_money:
            text = RE_MONEY.sub(" [MONEY] ", text)

        # 7. Phone Number Normalization
        if self.replace_phone:
            text = RE_PHONE.sub(" [PHONE] ", text)

        # 8. Whitespace Normalization
        if self.normalize_whitespace:
            text = RE_MULTIPLE_SPACES.sub(" ", text)
            text = RE_MULTIPLE_NEWLINES.sub("\n\n", text)
            text = text.strip()

        # 9. Optional Lowercasing
        if self.lowercase:
            text = text.lower()

        return text

    def format_email(
        self,
        subject: Optional[str],
        body: Optional[str],
        part_mode: Optional[str] = None,
    ) -> str:
        """
        Formats subject and body into a single structured string.
        """
        mode = part_mode or self.part_mode
        clean_subj = self.clean_text(subject)
        clean_body = self.clean_text(body)

        subj_token = clean_subj if clean_subj else "[EMPTY]"
        body_token = clean_body if clean_body else "[EMPTY]"

        if mode == "subject_only":
            return f"[SUBJECT] {subj_token}"
        elif mode == "body_only":
            return f"[BODY] {body_token}"
        else:  # "both"
            return f"[SUBJECT] {subj_token} [BODY] {body_token}"

    def get_config(self) -> Dict[str, Any]:
        """Returns preprocessor configuration dictionary for provenance and reproducibility."""
        return {
            "version": self.version,
            "url_mode": self.url_mode,
            "strip_html": self.strip_html,
            "normalize_whitespace": self.normalize_whitespace,
            "replace_email": self.replace_email,
            "replace_money": self.replace_money,
            "replace_phone": self.replace_phone,
            "lowercase": self.lowercase,
            "part_mode": self.part_mode,
        }
