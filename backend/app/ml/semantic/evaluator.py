"""
Comprehensive evaluation suite for Phase D3 Semantic NLP:
Multi-class & security metrics, short-text stress testing, source-aware breakdowns, and error analysis.
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    precision_recall_curve,
    auc,
    roc_auc_score,
    confusion_matrix,
    log_loss,
)
from app.ml.semantic.calibrator import compute_ece


def evaluate_predictions(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes standard multiclass, security, calibration, and confusion metrics.
    """
    if classes is None:
        classes = ["legitimate", "spam", "phishing"]

    y_pred = np.argmax(y_prob, axis=1)
    acc = float(accuracy_score(y_true, y_pred))

    prec, rec, f1, supp = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1, 2], average=None, zero_division=0
    )
    macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # Phishing-specific binary evaluation (class 2)
    phish_mask = (y_true == 2).astype(int)
    phish_probs = y_prob[:, 2] if y_prob.shape[1] > 2 else y_prob[:, -1]

    if np.sum(phish_mask) > 0 and np.sum(phish_mask) < len(phish_mask):
        p_prec, p_rec, _ = precision_recall_curve(phish_mask, phish_probs)
        phish_pr_auc = float(auc(p_rec, p_prec))
        try:
            phish_roc_auc = float(roc_auc_score(phish_mask, phish_probs))
        except Exception:
            phish_roc_auc = None
    else:
        phish_pr_auc = None
        phish_roc_auc = None

    # Multi-class calibration metrics
    present_classes = np.unique(y_true)
    num_classes = y_prob.shape[1]
    one_hot = np.zeros((len(y_true), num_classes))
    for i, c in enumerate(y_true):
        if 0 <= c < num_classes:
            one_hot[i, c] = 1.0

    brier = float(np.mean(np.sum((y_prob - one_hot) ** 2, axis=1)))
    ece = compute_ece(y_prob, y_true)

    eps = 1e-12
    ll = -float(np.mean(np.sum(one_hot * np.log(np.clip(y_prob, eps, 1.0)), axis=1)))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist()

    res = {
        "accuracy": round(acc, 4),
        "macro_precision": round(float(macro_prec), 4),
        "macro_recall": round(float(macro_rec), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_precision": round(float(weighted_prec), 4),
        "weighted_recall": round(float(weighted_rec), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "per_class": {},
        "phishing_metrics": {
            "precision": round(float(prec[2]), 4),
            "recall": round(float(rec[2]), 4),
            "f1": round(float(f1[2]), 4),
            "pr_auc": round(phish_pr_auc, 4) if phish_pr_auc is not None else None,
            "roc_auc": round(phish_roc_auc, 4) if phish_roc_auc is not None else None,
        },
        "brier_score": round(brier, 4),
        "ece": round(ece, 4),
        "log_loss": round(ll, 4),
        "confusion_matrix": cm,
    }

    for idx, cname in enumerate(classes):
        res["per_class"][cname] = {
            "precision": round(float(prec[idx]), 4),
            "recall": round(float(rec[idx]), 4),
            "f1": round(float(f1[idx]), 4),
            "support": int(supp[idx]),
        }

    return res


def evaluate_short_text_robustness(
    bodies: List[str],
    y_true: np.ndarray,
    y_prob: np.ndarray,
) -> Dict[str, Any]:
    """
    Evaluates performance partitioned across text length buckets:
    <5 words, 5-10, 10-20, 20-50, >50 words.
    """
    word_counts = np.array([len(str(b).split()) for b in bodies])
    buckets = [
        ("<5", (word_counts < 5)),
        ("5_10", (word_counts >= 5) & (word_counts <= 10)),
        ("10_20", (word_counts > 10) & (word_counts <= 20)),
        ("20_50", (word_counts > 20) & (word_counts <= 50)),
        (">50", (word_counts > 50)),
    ]

    results = {}
    for b_name, mask in buckets:
        count = int(np.sum(mask))
        if count == 0:
            results[b_name] = {"count": 0}
            continue

        sub_true = y_true[mask]
        sub_prob = y_prob[mask]
        sub_metrics = evaluate_predictions(sub_true, sub_prob)
        results[b_name] = {
            "count": count,
            "accuracy": sub_metrics["accuracy"],
            "macro_f1": sub_metrics["macro_f1"],
            "phishing_precision": sub_metrics["phishing_metrics"]["precision"],
            "phishing_recall": sub_metrics["phishing_metrics"]["recall"],
            "phishing_f1": sub_metrics["phishing_metrics"]["f1"],
            "phishing_pr_auc": sub_metrics["phishing_metrics"]["pr_auc"],
            "class_distribution": {
                "legitimate": int(np.sum(sub_true == 0)),
                "spam": int(np.sum(sub_true == 1)),
                "phishing": int(np.sum(sub_true == 2)),
            },
        }

    return results


def evaluate_source_generalization(
    sources: List[str],
    y_true: np.ndarray,
    y_prob: np.ndarray,
) -> Dict[str, Any]:
    """
    Evaluates model performance stratified by origin dataset.
    """
    sources_arr = np.array(sources)
    unique_sources = sorted(list(set(sources)))
    res = {}

    for src in unique_sources:
        mask = (sources_arr == src)
        count = int(np.sum(mask))
        sub_true = y_true[mask]
        sub_prob = y_prob[mask]

        sub_metrics = evaluate_predictions(sub_true, sub_prob)
        res[src] = {
            "sample_count": count,
            "accuracy": sub_metrics["accuracy"],
            "macro_f1": sub_metrics["macro_f1"],
            "phishing_precision": sub_metrics["phishing_metrics"]["precision"],
            "phishing_recall": sub_metrics["phishing_metrics"]["recall"],
            "phishing_f1": sub_metrics["phishing_metrics"]["f1"],
            "phishing_pr_auc": sub_metrics["phishing_metrics"]["pr_auc"],
            "classes_present": [int(c) for c in np.unique(sub_true)],
        }

    return res


def analyze_model_errors(
    texts: List[str],
    record_ids: List[str],
    sources: List[str],
    y_true: np.ndarray,
    y_prob: np.ndarray,
    max_cases_per_type: int = 5,
) -> Dict[str, Any]:
    """
    Performs deep failure analysis across prediction quadrants and confidence bands.
    """
    y_pred = np.argmax(y_prob, axis=1)
    confidences = np.max(y_prob, axis=1)
    correct_mask = (y_pred == y_true)

    label_names = {0: "legitimate", 1: "spam", 2: "phishing"}
    analysis: Dict[str, Any] = {
        "overall_summary": {
            "total_samples": len(y_true),
            "correct_count": int(np.sum(correct_mask)),
            "incorrect_count": int(np.sum(~correct_mask)),
            "mean_confidence_correct": round(float(np.mean(confidences[correct_mask])), 4) if np.any(correct_mask) else 0.0,
            "mean_confidence_incorrect": round(float(np.mean(confidences[~correct_mask])), 4) if np.any(~correct_mask) else 0.0,
        },
        "error_quadrants": {},
        "overconfident_errors": [],
    }

    # Quadrant breakdown
    quadrants = [
        (0, 1, "legitimate_to_spam"),
        (0, 2, "legitimate_to_phishing"),
        (1, 0, "spam_to_legitimate"),
        (1, 2, "spam_to_phishing"),
        (2, 0, "phishing_to_legitimate"),
        (2, 1, "phishing_to_spam"),
    ]

    for t_c, p_c, q_name in quadrants:
        q_mask = (y_true == t_c) & (y_pred == p_c)
        q_count = int(np.sum(q_mask))
        case_studies = []

        if q_count > 0:
            idxs = np.where(q_mask)[0]
            # sort by confidence descending (most confident mistakes first)
            sorted_idxs = idxs[np.argsort(-confidences[idxs])][:max_cases_per_type]
            for idx in sorted_idxs:
                sample_text = str(texts[idx])
                # Redacted brief excerpt (up to 120 chars)
                excerpt = sample_text[:120].replace("\n", " ") + ("..." if len(sample_text) > 120 else "")
                case_studies.append({
                    "record_id": str(record_ids[idx]),
                    "source": str(sources[idx]),
                    "confidence": round(float(confidences[idx]), 4),
                    "probabilities": {
                        "legitimate": round(float(y_prob[idx, 0]), 4),
                        "spam": round(float(y_prob[idx, 1]), 4),
                        "phishing": round(float(y_prob[idx, 2]), 4),
                    },
                    "text_excerpt": excerpt,
                })

        analysis["error_quadrants"][q_name] = {
            "count": q_count,
            "pct_of_true_class": round(float(q_count / max(1, np.sum(y_true == t_c)) * 100.0), 2),
            "mean_confidence": round(float(np.mean(confidences[q_mask])), 4) if q_count > 0 else 0.0,
            "cases": case_studies,
        }

    return analysis
