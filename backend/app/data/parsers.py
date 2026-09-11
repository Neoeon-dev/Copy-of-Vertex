"""
Source-Aware Raw Email Parsers for VERTEX.
Converts heterogeneous raw sources (Parquet, RFC 822 .eml, CSV)
into the immutable CanonicalEmailRecord schema.
Preserves original labels and metadata while enforcing the VERTEX taxonomy.
"""
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import pandas as pd
import hashlib
import os
import re

from app.data.schema import CanonicalEmailRecord, compute_content_hash
from app.data.text_normalizer import (
    normalize_email_body_and_subject,
    extract_urls_safely,
    sanitize_null_bytes,
)
from app.parsers.mime_parser import parse_email


def parse_hf_seven_phishing_parquet(
    parquet_path: Path,
    max_records: Optional[int] = None,
) -> List[CanonicalEmailRecord]:
    """
    Parses HuggingFace puyang2025/seven-phishing-email-datasets parquet partition.
    Schema: text, subject, label, sender, receiver, date, urls, dataset_name
    """
    df = pd.read_parquet(parquet_path)
    if max_records and len(df) > max_records:
        df = df.iloc[:max_records]

    records: List[CanonicalEmailRecord] = []
    for idx, row in df.iterrows():
        raw_text = str(row.get("text") or "")
        raw_subj = str(row.get("subject") or "")
        orig_lbl = str(row.get("label", ""))
        ds_name = str(row.get("dataset_name") or "unknown_subdataset")
        sender = str(row.get("sender") or "") if pd.notna(row.get("sender")) else None
        receiver = str(row.get("receiver") or "") if pd.notna(row.get("receiver")) else None
        date_val = str(row.get("date") or "") if pd.notna(row.get("date")) else None

        clean_sub, clean_body, extracted_urls = normalize_email_body_and_subject(
            subject=raw_subj, body=raw_text, is_html=False
        )
        if not clean_body.strip():
            continue  # reject completely empty records

        # Label normalization preserving source semantics
        # 0 = legitimate/ham across all components
        if orig_lbl in ("0", "0.0", "ham"):
            norm_lbl = "legitimate"
            threat = "clean"
        elif orig_lbl in ("1", "1.0", "spam", "phish"):
            if ds_name.upper() in ("CEAS-08", "CEAS_08"):
                norm_lbl = "phishing"
                threat = "generic_phish"
            elif "TREC" in ds_name.upper() or "ASSASSIN" in ds_name.upper() or "LING" in ds_name.upper():
                norm_lbl = "spam"
                threat = "generic_spam"
            else:
                norm_lbl = "phishing"
                threat = "generic_phish"
        else:
            norm_lbl = "unknown"
            threat = "unknown"

        c_hash = compute_content_hash(clean_sub, clean_body)
        rec = CanonicalEmailRecord(
            record_id=f"hf_{ds_name.lower()}_{c_hash[:12]}",
            source_dataset=f"hf_seven_phishing/{ds_name}",
            source_record_id=f"{parquet_path.stem}_{idx}",
            original_label=orig_lbl,
            normalized_label=norm_lbl,
            threat_type=threat,
            subject=clean_sub or None,
            body=clean_body,
            sender=sender,
            recipient=receiver,
            date=date_val,
            raw_email_available=False,
            url_count=len(extracted_urls),
            attachment_count=0,
            has_html=False,
            has_headers=bool(sender or receiver),
            dataset_version="1.0.0",
            license="Research/Educational (Multi-source public)",
            content_hash=c_hash,
        )
        records.append(rec)

    return records


def parse_spamassassin_raw_eml(
    eml_file_path: Path,
    original_corpus_label: str,  # "easy_ham", "spam", etc.
) -> Optional[CanonicalEmailRecord]:
    """
    Parses an authentic raw RFC 822 email from SpamAssassin public corpus
    using VERTEX MIME parser.
    """
    try:
        raw_bytes = eml_file_path.read_bytes()
    except Exception:
        return None

    if not raw_bytes:
        return None

    try:
        parsed = parse_email(raw_bytes)
    except Exception:
        return None

    body = parsed.body_text or parsed.body_html or ""
    clean_sub, clean_body, extracted_urls = normalize_email_body_and_subject(
        subject=parsed.subject,
        body=body,
        is_html=bool(not parsed.body_text and parsed.body_html),
    )

    if not clean_body.strip():
        return None

    if "ham" in original_corpus_label.lower():
        norm_lbl = "legitimate"
        threat = "clean"
    else:
        norm_lbl = "spam"
        threat = "generic_spam"

    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    c_hash = compute_content_hash(clean_sub, clean_body)

    rec = CanonicalEmailRecord(
        record_id=f"sa_{c_hash[:12]}",
        source_dataset="spamassassin_public_corpus",
        source_record_id=eml_file_path.name,
        original_label=original_corpus_label,
        normalized_label=norm_lbl,
        threat_type=threat,
        subject=clean_sub or None,
        body=clean_body,
        sender=parsed.sender,
        recipient=parsed.to,
        cc=parsed.cc,
        reply_to=parsed.reply_to,
        date=parsed.date,
        message_id=parsed.message_id,
        raw_email_available=True,
        raw_file_path=str(eml_file_path),
        url_count=len(extracted_urls),
        attachment_count=len(parsed.attachments),
        has_html=bool(parsed.body_html),
        has_headers=len(parsed.headers) > 0,
        dataset_version="20030228",
        license="Apache-2.0",
        content_hash=c_hash,
        raw_hash=raw_hash,
    )
    return rec


def parse_zenodo_curated_csv(
    csv_path: Path,
    dataset_name: str,
    threat_type_hint: Optional[str] = None,
    max_records: Optional[int] = None,
) -> List[CanonicalEmailRecord]:
    """
    Parses curated CSV from Zenodo (DOI: 10.5281/zenodo.8339691).
    Format: sender, receiver, date, subject, body, urls, label
    """
    df = pd.read_csv(csv_path)
    if max_records and len(df) > max_records:
        df = df.iloc[:max_records]

    records: List[CanonicalEmailRecord] = []
    for idx, row in df.iterrows():
        raw_text = str(row.get("body") or "")
        raw_subj = str(row.get("subject") or "")
        orig_lbl = str(row.get("label", ""))
        sender = str(row.get("sender") or "") if pd.notna(row.get("sender")) else None
        receiver = str(row.get("receiver") or "") if pd.notna(row.get("receiver")) else None
        date_val = str(row.get("date") or "") if pd.notna(row.get("date")) else None

        clean_sub, clean_body, extracted_urls = normalize_email_body_and_subject(
            subject=raw_subj, body=raw_text, is_html=False
        )
        if not clean_body.strip():
            continue

        if orig_lbl in ("1", "1.0", "phish", "phishing"):
            norm_lbl = "phishing"
            threat = threat_type_hint or "generic_phish"
        elif orig_lbl in ("0", "0.0", "ham", "clean", "safe"):
            norm_lbl = "legitimate"
            threat = "clean"
        else:
            norm_lbl = "suspicious"
            threat = "unknown"

        c_hash = compute_content_hash(clean_sub, clean_body)
        rec = CanonicalEmailRecord(
            record_id=f"zen_{dataset_name.lower()}_{c_hash[:12]}",
            source_dataset=f"zenodo_8339691/{dataset_name}",
            source_record_id=f"{csv_path.stem}_{idx}",
            original_label=orig_lbl,
            normalized_label=norm_lbl,
            threat_type=threat,
            subject=clean_sub or None,
            body=clean_body,
            sender=sender,
            recipient=receiver,
            date=date_val,
            raw_email_available=False,
            url_count=len(extracted_urls),
            attachment_count=0,
            has_html=False,
            has_headers=bool(sender or receiver),
            dataset_version="DOI:10.5281/zenodo.8339691",
            license="Creative Commons Attribution 4.0 International",
            content_hash=c_hash,
        )
        records.append(rec)

    return records


def parse_validation_emails_csv(
    csv_path: Path,
) -> List[CanonicalEmailRecord]:
    """
    Parses Zenodo Phishing Validation Emails (DOI: 10.5281/zenodo.13474746).
    Schema: Email Text, Email Type ('Safe Email', 'Phishing Email')
    CRITICAL: This is an independent holdout evaluation resource!
    """
    df = pd.read_csv(csv_path)
    records: List[CanonicalEmailRecord] = []

    for idx, row in df.iterrows():
        raw_text = str(row.get("Email Text") or "")
        orig_type = str(row.get("Email Type") or "").strip()

        clean_sub, clean_body, extracted_urls = normalize_email_body_and_subject(
            subject="", body=raw_text, is_html=False
        )
        if not clean_body.strip():
            continue

        if "safe" in orig_type.lower():
            norm_lbl = "legitimate"
            threat = "clean"
        elif "phish" in orig_type.lower():
            norm_lbl = "phishing"
            threat = "generic_phish"
        else:
            norm_lbl = "unknown"
            threat = "unknown"

        c_hash = compute_content_hash("", clean_body)
        rec = CanonicalEmailRecord(
            record_id=f"val_holdout_{c_hash[:12]}",
            source_dataset="zenodo_validation_holdout_13474746",
            source_record_id=f"val_{idx}",
            original_label=orig_type,
            normalized_label=norm_lbl,
            threat_type=threat,
            subject=None,
            body=clean_body,
            raw_email_available=False,
            url_count=len(extracted_urls),
            attachment_count=0,
            has_html=False,
            has_headers=False,
            dataset_version="DOI:10.5281/zenodo.13474746",
            license="Creative Commons Attribution 4.0 International",
            content_hash=c_hash,
        )
        records.append(rec)

    return records
