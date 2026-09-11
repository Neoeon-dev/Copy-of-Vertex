"""
Automated Dataset Acquisition Utility for VERTEX.
Downloads approved external benchmark datasets with streaming,
progress tracking, SHA-256 integrity verification, and raw preservation.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import requests
import hashlib
import time
import os
import json

from app.data.checksum import calculate_sha256

USER_AGENT = "VERTEX-Dataset-Acquisition/1.0 (Cybersecurity Research; SIH26106)"

# Approved Data Sources Catalog
DATASET_CATALOG = {
    "hf_seven_eval": {
        "name": "Hugging Face Seven Phishing Email Datasets (eval partition)",
        "source_type": "huggingface",
        "url": "https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets/resolve/main/eval.parquet",
        "dest_rel_path": "raw/seven_phishing/eval.parquet",
        "license": "Research/Educational (Multi-source public)",
        "doi": None,
    },
    "hf_seven_test": {
        "name": "Hugging Face Seven Phishing Email Datasets (test partition)",
        "source_type": "huggingface",
        "url": "https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets/resolve/main/test.parquet",
        "dest_rel_path": "raw/seven_phishing/test.parquet",
        "license": "Research/Educational (Multi-source public)",
        "doi": None,
    },
    "spamassassin_easy_ham": {
        "name": "SpamAssassin Public Corpus (20030228 easy_ham)",
        "source_type": "apache_public_corpus",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "dest_rel_path": "raw/spamassassin/20030228_easy_ham.tar.bz2",
        "license": "Apache-2.0",
        "doi": None,
    },
    "spamassassin_spam": {
        "name": "SpamAssassin Public Corpus (20030228 spam)",
        "source_type": "apache_public_corpus",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "dest_rel_path": "raw/spamassassin/20030228_spam.tar.bz2",
        "license": "Apache-2.0",
        "doi": None,
    },
    "zenodo_validation_holdout": {
        "name": "Zenodo Phishing Validation Emails Dataset",
        "source_type": "zenodo",
        "url": "https://zenodo.org/api/records/13474746/files/Phishing_validation_emails.csv/content",
        "dest_rel_path": "raw/validation/Phishing_validation_emails.csv",
        "license": "Creative Commons Attribution 4.0 International",
        "doi": "10.5281/zenodo.13474746",
    },
    "zenodo_curated_nazario": {
        "name": "Zenodo Phishing Curated Datasets (Nazario)",
        "source_type": "zenodo",
        "url": "https://zenodo.org/api/records/8339691/files/Nazario.csv/content",
        "dest_rel_path": "raw/zenodo_curated/Nazario.csv",
        "license": "Creative Commons Attribution 4.0 International",
        "doi": "10.5281/zenodo.8339691",
    },
    "zenodo_curated_nigerian_fraud": {
        "name": "Zenodo Phishing Curated Datasets (Nigerian_Fraud)",
        "source_type": "zenodo",
        "url": "https://zenodo.org/api/records/8339691/files/Nigerian_Fraud.csv/content",
        "dest_rel_path": "raw/zenodo_curated/Nigerian_Fraud.csv",
        "license": "Creative Commons Attribution 4.0 International",
        "doi": "10.5281/zenodo.8339691",
    },
}

# Catalog of Evaluated but Deferred Sources
DEFERRED_CATALOG = {
    "zenodo_17314806": {
        "name": "Zenodo Phishing-Email-Detection-Dataset",
        "doi": "10.5281/zenodo.17314806",
        "status": "DEFERRED / SKIPPED",
        "reason": (
            "Source contains Merged_Dataset.csv (391 MB) and Balanced_Dataset.csv (358 MB). "
            "Inspection confirmed this is a derivative compilation of nine public corpora "
            "(Nazario, CEAS, Enron, SpamAssassin, etc.) that VERTEX acquires directly from primary "
            "curated repositories. Downloading 391 MB of redundant merged records would violate the "
            "provenance clarity directive and cause massive duplication without novel data."
        ),
    },
    "cmu_enron_full_raw": {
        "name": "CMU Enron Full Maildir Archive",
        "url": "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
        "status": "DEFERRED / SUBSET USED",
        "reason": (
            "Full archive is 443 MB compressed / 1.7 GB uncompressed containing corporate correspondence "
            "with severe PII concerns and potential bias. VERTEX instead utilizes the curated and balanced "
            "Enron partition from HuggingFace seven-phishing-email-datasets."
        ),
    },
}


def download_file(url: str, dest_path: Path, expected_sha: Optional[str] = None) -> Tuple[str, int]:
    """
    Downloads a remote file with streaming chunks, computes SHA-256,
    and checks against expected hash if provided.
    Returns (sha256, size_bytes).
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_path.with_suffix(dest_path.suffix + ".part")

    headers = {"User-Agent": USER_AGENT}
    hasher = hashlib.sha256()
    size = 0

    with requests.get(url, headers=headers, stream=True, timeout=60) as response:
        response.raise_for_status()
        with open(temp_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    hasher.update(chunk)
                    size += len(chunk)

    actual_sha = hasher.hexdigest()
    if expected_sha and actual_sha != expected_sha:
        temp_path.unlink(missing_ok=True)
        raise ValueError(
            f"Checksum mismatch for {url}: expected {expected_sha}, got {actual_sha}"
        )

    # Atomic move
    temp_path.replace(dest_path)
    return (actual_sha, size)


def acquire_all_approved_datasets(data_root: Path) -> Dict[str, Any]:
    """
    Executes acquisition of all approved datasets in catalog.
    Returns structured acquisition report.
    """
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "acquired_sources": {},
        "deferred_sources": DEFERRED_CATALOG,
    }

    for key, spec in DATASET_CATALOG.items():
        dest = data_root / spec["dest_rel_path"]
        print(f"[*] Acquiring {key}: {spec['name']} -> {dest}...")
        
        # If already downloaded and valid, compute hash
        if dest.exists() and dest.stat().st_size > 0:
            sha = calculate_sha256(dest)
            size = dest.stat().st_size
            print(f"    Already present: {size} bytes, sha256={sha[:16]}...")
        else:
            t0 = time.time()
            sha, size = download_file(spec["url"], dest)
            dt = time.time() - t0
            print(f"    Downloaded in {dt:.2f}s: {size} bytes, sha256={sha[:16]}...")

        report["acquired_sources"][key] = {
            "name": spec["name"],
            "url": spec["url"],
            "local_path": str(dest.relative_to(data_root)),
            "size_bytes": size,
            "sha256": sha,
            "license": spec["license"],
            "doi": spec["doi"],
            "source_type": spec["source_type"],
        }

    return report
