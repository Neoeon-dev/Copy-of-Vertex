"""
Forensic Error Analysis Engine for VERTEX Tabular ML.
Performs systematic diagnostics on misclassifications:
- High-confidence False Positives (Legitimate classified as Phishing/Spam)
- High-confidence False Negatives (Phishing classified as Legitimate/Spam)
- Cross-threat confusion (Phishing vs Spam)
Correlates errors with forensic indicators (missing raw evidence, broken auth, url absence, source dataset).
"""
from typing import Dict, Any, List, Optional
import numpy as np

from app.ml.version import TARGET_CLASSES, LABEL_TO_INT, INT_TO_LABEL


def analyze_misclassifications(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    feature_names: List[str],
    X: np.ndarray,
    record_ids: Optional[List[str]] = None,
    source_datasets: Optional[List[str]] = None,
    raw_evidence: Optional[List[float]] = None,
    max_cases_per_type: int = 10,
) -> Dict[str, Any]:
    """
    Analyzes misclassification patterns, high-confidence errors, and forensic correlates.
    """
    y_pred = np.argmax(y_prob, axis=1)
    confidences = np.max(y_prob, axis=1)
    n_samples = len(y_true)

    rec_ids = record_ids if record_ids is not None else [f"sample_{i}" for i in range(n_samples)]
    sources = source_datasets if source_datasets is not None else ["unknown"] * n_samples
    raw_ev = raw_evidence if raw_evidence is not None else [1.0] * n_samples

    feat_map = {name: idx for idx, name in enumerate(feature_names)}

    legit_idx = LABEL_TO_INT.get("legitimate", 0)
    spam_idx = LABEL_TO_INT.get("spam", 1)
    phish_idx = LABEL_TO_INT.get("phishing", 2)

    # 1. Categories
    # False Positives: True Legit, Pred Phish or Spam
    fp_mask = (y_true == legit_idx) & (y_pred != legit_idx)
    fp_phish_mask = (y_true == legit_idx) & (y_pred == phish_idx)
    fp_spam_mask = (y_true == legit_idx) & (y_pred == spam_idx)

    # False Negatives: True Phish, Pred Legit or Spam
    fn_phish_mask = (y_true == phish_idx) & (y_pred != phish_idx)
    fn_to_legit_mask = (y_true == phish_idx) & (y_pred == legit_idx)
    fn_to_spam_mask = (y_true == phish_idx) & (y_pred == spam_idx)

    # Spam misclassified as Phish
    spam_to_phish_mask = (y_true == spam_idx) & (y_pred == phish_idx)

    total_errors = int(np.sum(y_true != y_pred))

    def extract_error_cases(mask: np.ndarray, sort_by_conf: bool = True) -> List[Dict[str, Any]]:
        indices = np.where(mask)[0]
        if len(indices) == 0:
            return []
        if sort_by_conf:
            # Sort by confidence descending
            indices = indices[np.argsort(-confidences[indices])]
        selected = indices[:max_cases_per_type]

        cases = []
        for idx in selected:
            # Key feature values
            f_vals = {}
            for key in [
                "auth_spf_pass", "auth_dkim_pass", "auth_dmarc_pass",
                "url_count", "url_suspicious_count", "bec_urgency_words_count",
                "msg_subject_length", "msg_has_html", "identity_from_reply_mismatch"
            ]:
                if key in feat_map:
                    f_vals[key] = float(round(float(X[idx, feat_map[key]]), 3))

            cases.append({
                "record_id": rec_ids[idx],
                "source_dataset": sources[idx],
                "raw_evidence": float(raw_ev[idx]),
                "true_label": INT_TO_LABEL.get(y_true[idx], "unknown"),
                "predicted_label": INT_TO_LABEL.get(y_pred[idx], "unknown"),
                "confidence": float(round(float(confidences[idx]), 4)),
                "probabilities": {
                    INT_TO_LABEL[c]: float(round(float(y_prob[idx, c]), 4))
                    for c in range(len(TARGET_CLASSES))
                },
                "diagnostic_features": f_vals,
            })
        return cases

    # Compute correlate statistics
    def correlate_stats(mask: np.ndarray) -> Dict[str, Any]:
        count = int(np.sum(mask))
        if count == 0:
            return {"count": 0}
        sub_indices = np.where(mask)[0]

        # Raw evidence missing fraction
        sub_raw = [raw_ev[i] for i in sub_indices]
        pct_no_raw = float(round(float(np.mean([1.0 if r == 0.0 else 0.0 for r in sub_raw])) * 100, 2))

        # Auth failures
        spf_fail_pct = 0.0
        if "auth_spf_pass" in feat_map:
            spf_col = X[sub_indices, feat_map["auth_spf_pass"]]
            spf_fail_pct = float(round(float(np.mean(spf_col <= 0)) * 100, 2))

        dkim_fail_pct = 0.0
        if "auth_dkim_pass" in feat_map:
            dkim_col = X[sub_indices, feat_map["auth_dkim_pass"]]
            dkim_fail_pct = float(round(float(np.mean(dkim_col <= 0)) * 100, 2))

        # Sources distribution
        err_sources = [sources[i] for i in sub_indices]
        from collections import Counter
        top_srcs = dict(Counter(err_sources).most_common(5))

        return {
            "count": count,
            "pct_missing_raw_evidence": pct_no_raw,
            "pct_spf_failed_or_missing": spf_fail_pct,
            "pct_dkim_failed_or_missing": dkim_fail_pct,
            "top_source_datasets": top_srcs,
        }

    return {
        "summary": {
            "total_samples": n_samples,
            "total_errors": total_errors,
            "error_rate": float(round(total_errors / max(n_samples, 1), 4)),
            "false_positives_phishing": int(np.sum(fp_phish_mask)),
            "false_positives_spam": int(np.sum(fp_spam_mask)),
            "false_negatives_phishing_as_legit": int(np.sum(fn_to_legit_mask)),
            "false_negatives_phishing_as_spam": int(np.sum(fn_to_spam_mask)),
            "spam_confused_as_phishing": int(np.sum(spam_to_phish_mask)),
        },
        "correlates": {
            "false_positives_phishing": correlate_stats(fp_phish_mask),
            "false_negatives_phishing": correlate_stats(fn_phish_mask),
            "phishing_to_spam_confusion": correlate_stats(fn_to_spam_mask),
        },
        "top_cases": {
            "highest_confidence_false_positives": extract_error_cases(fp_phish_mask),
            "highest_confidence_false_negatives": extract_error_cases(fn_to_legit_mask),
            "phishing_classified_as_spam": extract_error_cases(fn_to_spam_mask),
        },
    }
