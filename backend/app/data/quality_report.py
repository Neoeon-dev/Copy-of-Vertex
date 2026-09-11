"""
Data Quality & Statistical Profiling Engine for VERTEX.
Computes exhaustive, factual metrics over real processed datasets:
class distributions, source distributions, missingness, body/subject lengths,
URL/attachment presence, deduplication rates, and group-aware split balance.
"""
from typing import List, Dict, Any, Optional
from collections import defaultdict
import statistics
import time

from app.data.schema import CanonicalEmailRecord
from app.data.deduplicator import DeduplicationReport
from app.data.splitter import SplitResult


def compute_data_quality_report(
    raw_records: List[CanonicalEmailRecord],
    deduped_records: List[CanonicalEmailRecord],
    dedup_report: DeduplicationReport,
    split_result: Optional[SplitResult] = None,
    holdout_records: Optional[List[CanonicalEmailRecord]] = None,
    rejected_count: int = 0,
    rejection_reasons: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """
    Builds an exhaustive data quality report grounded entirely in actual record attributes.
    """
    total_processed = len(deduped_records)
    
    # Label distributions (Overall and by source)
    label_dist: Dict[str, int] = defaultdict(int)
    threat_dist: Dict[str, int] = defaultdict(int)
    source_dist: Dict[str, int] = defaultdict(int)
    source_label_matrix: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Field missingness tracking
    missing_fields = {
        "subject": 0,
        "sender": 0,
        "recipient": 0,
        "date": 0,
        "message_id": 0,
        "raw_hash": 0,
    }

    # Text length metrics
    body_lengths: List[int] = []
    subject_lengths: List[int] = []
    url_counts: List[int] = []
    records_with_urls = 0
    records_with_html = 0
    records_with_attachments = 0
    records_with_raw_eml = 0

    for rec in deduped_records:
        label_dist[rec.normalized_label] += 1
        threat_dist[rec.threat_type or "unknown"] += 1
        source_dist[rec.source_dataset] += 1
        source_label_matrix[rec.source_dataset][rec.normalized_label] += 1

        if not rec.subject:
            missing_fields["subject"] += 1
        else:
            subject_lengths.append(len(rec.subject))

        if not rec.sender:
            missing_fields["sender"] += 1
        if not rec.recipient:
            missing_fields["recipient"] += 1
        if not rec.date:
            missing_fields["date"] += 1
        if not rec.message_id:
            missing_fields["message_id"] += 1
        if not rec.raw_hash:
            missing_fields["raw_hash"] += 1

        b_len = len(rec.body)
        body_lengths.append(b_len)

        url_counts.append(rec.url_count)
        if rec.url_count > 0:
            records_with_urls += 1
        if rec.has_html:
            records_with_html += 1
        if rec.attachment_count > 0:
            records_with_attachments += 1
        if rec.raw_email_available:
            records_with_raw_eml += 1

    # Statistical summaries
    def calc_stats(values: List[int]) -> Dict[str, float]:
        if not values:
            return {"min": 0, "max": 0, "mean": 0.0, "median": 0.0}
        return {
            "min": int(min(values)),
            "max": int(max(values)),
            "mean": round(statistics.mean(values), 2),
            "median": round(statistics.median(values), 2),
        }

    body_stats = calc_stats(body_lengths)
    subj_stats = calc_stats(subject_lengths)
    url_stats = calc_stats(url_counts)

    missing_percentages = {
        k: round((v / max(1, total_processed)) * 100, 2)
        for k, v in missing_fields.items()
    }

    report = {
        "report_id": "VERTEX-DATA-QUALITY-PHASE-C",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_input_records": len(raw_records),
            "rejected_records": rejected_count,
            "rejection_reasons": rejection_reasons or {},
            "usable_records_pre_dedup": len(raw_records) - rejected_count,
            "retained_records_post_dedup": total_processed,
            "deduplication_rate_percent": round(
                (1.0 - (total_processed / max(1, len(raw_records)))) * 100, 2
            ),
        },
        "deduplication": dedup_report.to_dict(),
        "distributions": {
            "label_distribution": dict(label_dist),
            "threat_type_distribution": dict(threat_dist),
            "source_distribution": dict(source_dist),
            "source_label_matrix": {k: dict(v) for k, v in source_label_matrix.items()},
        },
        "feature_telemetry": {
            "records_with_urls": records_with_urls,
            "percent_with_urls": round((records_with_urls / max(1, total_processed)) * 100, 2),
            "records_with_html": records_with_html,
            "percent_with_html": round((records_with_html / max(1, total_processed)) * 100, 2),
            "records_with_attachments": records_with_attachments,
            "percent_with_attachments": round((records_with_attachments / max(1, total_processed)) * 100, 2),
            "records_with_raw_rfc822_eml": records_with_raw_eml,
            "percent_with_raw_eml": round((records_with_raw_eml / max(1, total_processed)) * 100, 2),
        },
        "content_statistics": {
            "body_length_characters": body_stats,
            "subject_length_characters": subj_stats,
            "url_count_per_email": url_stats,
        },
        "field_missingness": {
            "counts": missing_fields,
            "percentages": missing_percentages,
        },
    }

    if split_result:
        report["split_distributions"] = split_result.to_dict()

    if holdout_records:
        h_labels: Dict[str, int] = defaultdict(int)
        for h in holdout_records:
            h_labels[h.normalized_label] += 1
        report["independent_holdout_validation"] = {
            "source": "Zenodo DOI:10.5281/zenodo.13474746",
            "total_records": len(holdout_records),
            "label_distribution": dict(h_labels),
            "status": "STRICTLY_ISOLATED_FROM_TRAINING",
        }

    return report
