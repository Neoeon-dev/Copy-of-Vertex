"""
Evidence Availability, Prediction Distribution, and Holdout Confusion Diagnostic Engine.
Measures forensic signal presence, analyzes probability distributions under domain shift,
and dissects holdout confusion patterns with concrete error case studies.
"""
from typing import Dict, Any, List, Tuple, Optional
from collections import Counter
import numpy as np

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.version import TARGET_CLASSES, INT_TO_LABEL, LABEL_TO_INT


def analyze_evidence_availability(
    splits: Dict[str, TabularDataset],
) -> Dict[str, Any]:
    """
    Compares availability rates of forensic evidence across dataset splits.
    Uses -1.0 sentinel convention from Phase D1.
    """
    feature_names = next(iter(splits.values())).feature_names
    feat_idx = {name: i for i, name in enumerate(feature_names)}

    evidence_indicators = {
        "raw_rfc822_available": None,  # extracted from metadata
        "headers_available": "msg_header_count",
        "spf_evidence_available": "auth_spf_pass",
        "dkim_evidence_available": "auth_dkim_pass",
        "dmarc_evidence_available": "auth_dmarc_pass",
        "relay_path_available": "relay_hop_count",
        "ip_infra_available": "ip_origin_is_private",
        "urls_detected": "url_count",
        "html_body_detected": "msg_has_html",
        "attachment_metadata_detected": "attach_count",
    }

    report: Dict[str, Dict[str, float]] = {}

    for split_name, ds in splits.items():
        n = ds.num_samples
        report[split_name] = {}

        # 1. Raw evidence rate
        raw_avail = sum(1.0 for r in ds.raw_evidence_available if r > 0.0)
        report[split_name]["raw_rfc822_available"] = float(round(raw_avail / max(n, 1), 4))

        # 2. Indicators based on feature values
        for indicator_name, col_name in evidence_indicators.items():
            if col_name is None:
                continue
            if col_name in feat_idx:
                col_vals = ds.X[:, feat_idx[col_name]]
                if indicator_name in ["urls_detected", "html_body_detected", "attachment_metadata_detected"]:
                    # Positive count
                    present = np.sum(col_vals > 0.0)
                else:
                    # Not missing sentinel (-1.0)
                    present = np.sum(col_vals != -1.0)
                report[split_name][indicator_name] = float(round(float(present) / max(n, 1), 4))
            else:
                report[split_name][indicator_name] = 0.0

    return report


def analyze_prediction_distributions(
    model: Any,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
) -> Dict[str, Any]:
    """
    Compares predicted probability distributions across Test and Holdout splits,
    broken down by true class.
    """
    test_probs = model.predict_proba(test_ds.X)
    test_preds = np.argmax(test_probs, axis=1)

    ho_probs = model.predict_proba(holdout_ds.X)
    ho_preds = np.argmax(ho_probs, axis=1)

    def summarize_probs(probs: np.ndarray, preds: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        confidences = np.max(probs, axis=1)
        pred_counts = dict(Counter([INT_TO_LABEL.get(p, str(p)) for p in preds]))

        by_class = {}
        for c_idx, c_name in enumerate(TARGET_CLASSES):
            mask = (y_true == c_idx)
            count = int(np.sum(mask))
            if count > 0:
                sub_probs = probs[mask]
                sub_preds = preds[mask]
                by_class[c_name] = {
                    "count": count,
                    "predicted_distribution": dict(Counter([INT_TO_LABEL.get(p, str(p)) for p in sub_preds])),
                    "mean_p_legitimate": float(round(float(np.mean(sub_probs[:, 0])), 4)),
                    "mean_p_spam": float(round(float(np.mean(sub_probs[:, 1])), 4)),
                    "mean_p_phishing": float(round(float(np.mean(sub_probs[:, 2])), 4)),
                    "mean_confidence": float(round(float(np.mean(confidences[mask])), 4)),
                }

        return {
            "total_samples": len(y_true),
            "predicted_distribution": pred_counts,
            "overall_mean_confidence": float(round(float(np.mean(confidences)), 4)),
            "per_true_class": by_class,
        }

    return {
        "test": summarize_probs(test_probs, test_preds, test_ds.y),
        "holdout": summarize_probs(ho_probs, ho_preds, holdout_ds.y),
    }


def analyze_holdout_confusion_patterns(
    model: Any,
    holdout_ds: TabularDataset,
) -> Dict[str, Any]:
    """
    Dissects the 4 error quadrants on the Holdout dataset:
    - Legitimate -> Phishing (FP Phish)
    - Legitimate -> Spam (FP Spam)
    - Phishing -> Legitimate (FN Phish)
    - Phishing -> Spam (Phish confused as Spam)
    Extracts forensic features and concrete case studies.
    """
    probs = model.predict_proba(holdout_ds.X)
    preds = np.argmax(probs, axis=1)
    confs = np.max(probs, axis=1)
    feature_names = holdout_ds.feature_names
    feat_idx = {name: i for i, name in enumerate(feature_names)}

    legit_idx = LABEL_TO_INT["legitimate"]
    spam_idx = LABEL_TO_INT["spam"]
    phish_idx = LABEL_TO_INT["phishing"]

    quadrants = {
        "legitimate_predicted_as_phishing": (holdout_ds.y == legit_idx) & (preds == phish_idx),
        "legitimate_predicted_as_spam": (holdout_ds.y == legit_idx) & (preds == spam_idx),
        "phishing_predicted_as_legitimate": (holdout_ds.y == phish_idx) & (preds == legit_idx),
        "phishing_predicted_as_spam": (holdout_ds.y == phish_idx) & (preds == spam_idx),
        "phishing_correctly_predicted": (holdout_ds.y == phish_idx) & (preds == phish_idx),
        "legitimate_correctly_predicted": (holdout_ds.y == legit_idx) & (preds == legit_idx),
    }

    results = {}
    case_studies = []

    for q_name, mask in quadrants.items():
        count = int(np.sum(mask))
        if count == 0:
            results[q_name] = {"count": 0, "pct_of_class": 0.0, "mean_confidence": 0.0}
            continue

        sub_confs = confs[mask]
        sub_probs = probs[mask]
        sub_indices = np.where(mask)[0]

        # Key diagnostic feature means
        diag_means = {}
        for key in [
            "msg_subject_length", "msg_body_length", "url_count",
            "auth_spf_pass", "auth_dkim_pass", "bec_urgency_words_count",
            "content_link_count", "msg_header_count"
        ]:
            if key in feat_idx:
                diag_means[key] = float(round(float(np.mean(holdout_ds.X[sub_indices, feat_idx[key]])), 3))

        true_class_name = "legitimate" if "legitimate" in q_name else "phishing"
        total_in_class = 1000.0  # holdout has 1000 legit, 1000 phish

        results[q_name] = {
            "count": count,
            "pct_of_class": float(round((count / total_in_class) * 100, 2)),
            "mean_confidence": float(round(float(np.mean(sub_confs)), 4)),
            "mean_probs": {
                "legitimate": float(round(float(np.mean(sub_probs[:, 0])), 4)),
                "spam": float(round(float(np.mean(sub_probs[:, 1])), 4)),
                "phishing": float(round(float(np.mean(sub_probs[:, 2])), 4)),
            },
            "diagnostic_feature_means": diag_means,
        }

        # Select top 2 case studies sorted by confidence
        sorted_sub = sub_indices[np.argsort(-confs[sub_indices])][:2]
        for idx in sorted_sub:
            case_studies.append({
                "quadrant": q_name,
                "record_id": holdout_ds.record_ids[idx] if idx < len(holdout_ds.record_ids) else f"ho_{idx}",
                "source_dataset": holdout_ds.source_datasets[idx] if idx < len(holdout_ds.source_datasets) else "unknown",
                "true_label": INT_TO_LABEL.get(holdout_ds.y[idx], "unknown"),
                "predicted_label": INT_TO_LABEL.get(preds[idx], "unknown"),
                "confidence": float(round(float(confs[idx]), 4)),
                "probabilities": {
                    "legitimate": float(round(float(probs[idx, 0]), 4)),
                    "spam": float(round(float(probs[idx, 1]), 4)),
                    "phishing": float(round(float(probs[idx, 2]), 4)),
                },
                "key_features": {
                    k: float(round(float(holdout_ds.X[idx, feat_idx[k]]), 3))
                    for k in ["url_count", "auth_spf_pass", "msg_subject_length", "msg_body_length", "bec_urgency_words_count"]
                    if k in feat_idx
                },
            })

    return {
        "confusion_quadrants": results,
        "case_studies": case_studies,
    }
