"""
Decision Threshold Analysis Engine for Phishing Detection in VERTEX.
Sweeps classification probability thresholds for the phishing class to evaluate trade-offs
between Precision, Recall, False Positive Rate (FPR), and F1 score for SOC triage workflows.
"""
from typing import Dict, Any, List, Optional
import numpy as np

from app.ml.version import LABEL_TO_INT


def analyze_phishing_thresholds(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    thresholds: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """
    Sweeps phishing probability thresholds and computes operational SOC metrics.
    """
    if thresholds is None:
        thresholds = [round(float(t), 2) for t in np.arange(0.05, 1.00, 0.05)]

    phish_idx = LABEL_TO_INT.get("phishing", 2)
    y_true_binary = (y_true == phish_idx).astype(int)
    phish_probs = y_prob[:, phish_idx]

    sweep_results: List[Dict[str, Any]] = []

    best_f1 = -1.0
    best_f1_threshold = 0.5
    high_recall_threshold = 0.5
    low_fpr_threshold = 0.5

    min_fpr_below_half_pct = float("inf")
    max_recall_above_95 = -1.0

    for thresh in thresholds:
        y_pred_binary = (phish_probs >= thresh).astype(int)

        tp = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
        fp = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
        fn = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
        tn = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))

        prec = float(round(tp / max(tp + fp, 1), 4))
        rec = float(round(tp / max(tp + fn, 1), 4))
        f1 = float(round(2 * prec * rec / max(prec + rec, 1e-6), 4))
        fpr = float(round(fp / max(fp + tn, 1), 4))
        fnr = float(round(fn / max(fn + tp, 1), 4))

        point = {
            "threshold": thresh,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "fpr": fpr,
            "fnr": fnr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }
        sweep_results.append(point)

        # Track optimal operating points
        if f1 > best_f1:
            best_f1 = f1
            best_f1_threshold = thresh

        # High recall point (recall >= 0.95, highest precision)
        if rec >= 0.95 and (rec > max_recall_above_95 or (rec == max_recall_above_95 and prec > sweep_results[-1]["precision"])):
            max_recall_above_95 = rec
            high_recall_threshold = thresh

        # Low FPR point (fpr <= 0.005, highest recall)
        if fpr <= 0.005:
            low_fpr_threshold = thresh

    # Recommendations
    recommendations = {
        "balanced_f1": {
            "threshold": best_f1_threshold,
            "metrics": next((p for p in sweep_results if p["threshold"] == best_f1_threshold), {}),
            "use_case": "Standard automated quarantine / SIEM alerting",
        },
        "high_recall_soc_triage": {
            "threshold": high_recall_threshold,
            "metrics": next((p for p in sweep_results if p["threshold"] == high_recall_threshold), {}),
            "use_case": "High-security environment / Deep inspection queue",
        },
        "low_fpr_blocking": {
            "threshold": low_fpr_threshold,
            "metrics": next((p for p in sweep_results if p["threshold"] == low_fpr_threshold), {}),
            "use_case": "Autonomous inline hard-block with minimal false alarm risk",
        },
    }

    return {
        "sweep": sweep_results,
        "recommendations": recommendations,
    }


def format_threshold_table(threshold_dict: Dict[str, Any]) -> str:
    """Generates Markdown table for decision threshold sweep."""
    sweep = threshold_dict.get("sweep", [])
    lines = [
        "| Threshold | Precision | Recall | F1 Score | FPR (Legit Blocked) | FNR (Phish Missed) |",
        "|:---------:|:---------:|:------:|:--------:|:-------------------:|:------------------:|",
    ]
    for p in sweep:
        lines.append(
            f"| {p['threshold']:^9.2f} | {p['precision']:^9.4f} | {p['recall']:^6.4f} | "
            f"{p['f1']:^8.4f} | {p['fpr']:^19.4f} | {p['fnr']:^18.4f} |"
        )
    return "\n".join(lines)
