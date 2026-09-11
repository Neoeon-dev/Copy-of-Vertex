"""
Canonical Email Record Schema for VERTEX.
Enforces standard schema, label taxonomy, and cryptographic content hashing.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import hashlib
import json
import re


# VERTEX Standard Label Taxonomy
VALID_NORMALIZED_LABELS = {
    "legitimate",  # Benign, clean email
    "phishing",    # Credential harvesting, social engineering, malicious link
    "spam",        # Unsolicited bulk email, commercial spam, marketing
    "suspicious",  # Anomaly detected, ambiguous intent, quarantined
    "unknown",     # Unclear / unclassified
}

VALID_THREAT_TYPES = {
    "clean",
    "generic_phish",
    "credential_harvesting",
    "advance_fee_fraud",
    "impersonation",
    "generic_spam",
    "unknown",
}


def compute_content_hash(subject: Optional[str], body: str) -> str:
    """
    Computes a deterministic SHA-256 hash of normalized subject and body.
    Normalizes whitespace and converts to UTF-8.
    """
    norm_subject = re.sub(r"\s+", " ", (subject or "")).strip().lower()
    norm_body = re.sub(r"\s+", " ", (body or "")).strip().lower()
    payload = f"{norm_subject}\n{norm_body}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class CanonicalEmailRecord:
    record_id: str
    source_dataset: str
    source_record_id: Optional[str]
    original_label: str
    normalized_label: str
    threat_type: Optional[str]
    subject: Optional[str]
    body: str
    sender: Optional[str] = None
    recipient: Optional[str] = None
    cc: Optional[str] = None
    reply_to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    raw_email_available: bool = False
    raw_file_path: Optional[str] = None
    url_count: int = 0
    attachment_count: int = 0
    has_html: bool = False
    has_headers: bool = False
    dataset_version: str = "1.0.0"
    license: str = "unknown"
    content_hash: str = ""
    raw_hash: Optional[str] = None

    def __post_init__(self):
        # Defend against list/dict types for address fields
        for field_name in ("sender", "recipient", "cc", "reply_to"):
            val = getattr(self, field_name)
            if isinstance(val, list):
                parts = []
                for item in val:
                    if isinstance(item, dict):
                        addr = item.get("address") or item.get("name")
                        if addr:
                            parts.append(str(addr))
                    elif item:
                        parts.append(str(item))
                setattr(self, field_name, ", ".join(parts) if parts else None)
            elif isinstance(val, dict):
                addr = val.get("address") or val.get("name")
                setattr(self, field_name, str(addr) if addr else None)
            elif val is not None:
                setattr(self, field_name, str(val))

        # Ensure date is always an ISO string or None
        if self.date is not None:
            if hasattr(self.date, "isoformat"):
                self.date = self.date.isoformat()
            else:
                self.date = str(self.date)

        if self.subject is not None:
            self.subject = str(self.subject)
        if self.message_id is not None:
            self.message_id = str(self.message_id)
        if self.raw_file_path is not None:
            self.raw_file_path = str(self.raw_file_path)
        if self.body is not None:
            self.body = str(self.body)

        if self.normalized_label not in VALID_NORMALIZED_LABELS:
            raise ValueError(
                f"Invalid normalized_label: {self.normalized_label}. "
                f"Must be one of {VALID_NORMALIZED_LABELS}"
            )
        if self.threat_type and self.threat_type not in VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: {self.threat_type}. "
                f"Must be one of {VALID_THREAT_TYPES}"
            )
        if not self.content_hash:
            self.content_hash = compute_content_hash(self.subject, self.body)
        if not self.record_id:
            self.record_id = f"rec_{self.content_hash[:16]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalEmailRecord":
        return cls(**data)
