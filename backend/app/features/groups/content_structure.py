"""
Feature Group 10: Content Structure & Textual Anomaly Telemetry.
Analyzes stylistic anomalies, punctuation densities, currency symbols,
hidden text tags, and unicode obfuscation.
"""
from typing import Dict, Any, Tuple, Optional
import string
import re

ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e"}
CURRENCY_SYMBOLS = {"$", "€", "£", "¥", "₹"}

HIDDEN_TEXT_PATTERN = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0\b|color\s*:\s*rgba?\([^)]+,\s*0\)|"
    r"color\s*:\s*(#fff|#ffffff|white)\s*;[^\>]*background(?:-color)?\s*:\s*(#fff|#ffffff|white))",
    re.IGNORECASE,
)


def extract_content_structure(
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic textual style, punctuation, and obfuscation signals.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    sub = subject or ""
    txt = body_text or ""
    html = body_html or ""
    combined = f"{sub} {txt}".strip()
    total_len = len(combined)

    if total_len == 0:
        feats["cnt_uppercase_ratio"] = 0.0
        feats["cnt_digit_ratio"] = 0.0
        feats["cnt_punctuation_ratio"] = 0.0
        feats["cnt_exclamation_count"] = 0.0
        feats["cnt_question_count"] = 0.0
        feats["cnt_currency_symbol_count"] = 0.0
        feats["cnt_excessive_capitalization"] = 0.0
        feats["cnt_repeated_chars_detected"] = 0.0
        feats["cnt_whitespace_anomaly"] = 0.0
        feats["cnt_html_text_ratio"] = 0.0
        feats["cnt_hidden_text_detected"] = 0.0
        feats["cnt_unicode_anomaly"] = 0.0
        return feats, exps

    # 1. Letter Ratios
    alpha_chars = [c for c in combined if c.isalpha()]
    alpha_count = len(alpha_chars)
    upper_count = sum(1 for c in alpha_chars if c.isupper())
    upper_ratio = float(upper_count / alpha_count) if alpha_count > 0 else 0.0
    feats["cnt_uppercase_ratio"] = round(upper_ratio, 4)

    # 2. Digit and Punctuation Ratios
    digit_count = sum(1 for c in combined if c.isdigit())
    feats["cnt_digit_ratio"] = round(float(digit_count / total_len), 4)

    punct_count = sum(1 for c in combined if c in string.punctuation)
    feats["cnt_punctuation_ratio"] = round(float(punct_count / total_len), 4)

    # 3. Specific Counts
    excl_count = combined.count("!")
    qmark_count = combined.count("?")
    feats["cnt_exclamation_count"] = float(excl_count)
    feats["cnt_question_count"] = float(qmark_count)

    curr_count = sum(1 for c in combined if c in CURRENCY_SYMBOLS)
    feats["cnt_currency_symbol_count"] = float(curr_count)

    # 4. Excessive Capitalization Flag
    excessive_caps = 1.0 if (upper_ratio > 0.35 and alpha_count >= 30) else 0.0
    feats["cnt_excessive_capitalization"] = excessive_caps

    # 5. Repeated Characters (4 or more identical consecutive chars)
    has_repeated = 1.0 if re.search(r"(.)\1{3,}", combined) else 0.0
    feats["cnt_repeated_chars_detected"] = has_repeated

    # 6. Whitespace Anomaly (e.g. 4+ blank lines)
    whitespace_anomaly = 1.0 if re.search(r"(\r?\n\s*){5,}", combined) else 0.0
    feats["cnt_whitespace_anomaly"] = whitespace_anomaly

    # 7. HTML to Text Ratio
    if html:
        tag_chars = len(re.findall(r"<[^>]+>", html))
        text_chars = len(txt) if txt else len(re.sub(r"<[^>]+>", "", html))
        feats["cnt_html_text_ratio"] = round(float(tag_chars / max(1, text_chars)), 4)
    else:
        feats["cnt_html_text_ratio"] = 0.0

    # 8. Hidden Text Detected in HTML
    has_hidden = 1.0 if (html and HIDDEN_TEXT_PATTERN.search(html)) else 0.0
    feats["cnt_hidden_text_detected"] = has_hidden

    # 9. Unicode Anomaly (zero-width characters or non-ASCII in subject)
    has_zero_width = any(zc in combined for zc in ZERO_WIDTH_CHARS)
    non_ascii_sub = any(ord(c) > 127 for c in sub)
    unicode_anomaly = 1.0 if (has_zero_width or non_ascii_sub) else 0.0
    feats["cnt_unicode_anomaly"] = unicode_anomaly

    return feats, exps
