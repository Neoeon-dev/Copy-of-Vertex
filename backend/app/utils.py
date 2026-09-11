"""Shared utility functions."""
from __future__ import annotations

import html
import re
from typing import Any


def get_headers_dict(headers_list) -> dict[str, str | list[str]]:
    """Convert stored EmailHeader rows to a dict.

    Multiple headers with the same name become a list.
    """
    headers: dict[str, str | list[str]] = {}
    for h in headers_list:
        key = h.name.lower()
        if key in headers:
            existing = headers[key]
            if isinstance(existing, list):
                existing.append(h.value)
            else:
                headers[key] = [existing, h.value]
        else:
            headers[key] = h.value
    return headers


def escape_html(text: str | None) -> str:
    """Escape HTML special characters to prevent XSS."""
    if text is None:
        return ""
    return html.escape(str(text))
