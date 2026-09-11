"""
Dataset Manifest Generation & Verification for VERTEX.
Produces reproducible JSON manifests capturing full data lineage,
SHA-256 integrity hashes, licensing, and record-level metrics.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import time

from app.data.schema import CanonicalEmailRecord
from app.data.checksum import calculate_sha256


def generate_dataset_manifest(
    acquisition_report: Dict[str, Any],
    source_records: Dict[str, List[CanonicalEmailRecord]],
    source_rejections: Dict[str, int],
    data_root: Path,
) -> Dict[str, Any]:
    """
    Constructs the master dataset manifest adhering to the Phase C specification.
    """
    sources_manifest = {}

    for src_key, records in source_records.items():
        acq_info = acquisition_report.get("acquired_sources", {}).get(src_key, {})
        local_rel = acq_info.get("local_path")
        file_path = data_root / local_rel if local_rel else None
        
        sha256_hash = acq_info.get("sha256")
        size_bytes = acq_info.get("size_bytes", 0)
        if file_path and file_path.exists() and not sha256_hash:
            sha256_hash = calculate_sha256(file_path)
            size_bytes = file_path.stat().st_size

        # Compute label distribution for this source
        label_dist: Dict[str, int] = {}
        for r in records:
            label_dist[r.normalized_label] = label_dist.get(r.normalized_label, 0) + 1

        rejections = source_rejections.get(src_key, 0)
        total_raw = len(records) + rejections

        sources_manifest[src_key] = {
            "dataset_name": acq_info.get("name", src_key),
            "source_url": acq_info.get("url"),
            "source_type": acq_info.get("source_type"),
            "doi": acq_info.get("doi"),
            "acquisition_timestamp": acquisition_report.get("timestamp"),
            "version": "1.0.0",
            "local_file": local_rel,
            "file_size_bytes": size_bytes,
            "sha256": sha256_hash,
            "license": acq_info.get("license", "unknown"),
            "record_count_raw": total_raw,
            "accepted_count": len(records),
            "rejected_count": rejections,
            "label_distribution": label_dist,
            "preprocessing_version": "VERTEX-Preprocess-v1.0",
            "provenance_notes": (
                f"Ingested and normalized via VERTEX Phase C pipeline from {acq_info.get('name')}. "
                f"Original labels preserved alongside VERTEX canonical taxonomy."
            ),
        }

    manifest = {
        "manifest_version": "1.0.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project": "VERTEX / MailTrace",
        "hackathon_compliance": "SIH26106 (Smart India Hackathon 2026)",
        "datasets": sources_manifest,
        "deferred_sources": acquisition_report.get("deferred_sources", {}),
    }

    return manifest
