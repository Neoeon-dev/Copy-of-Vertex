"""
Source-Aware Evaluation Engine for VERTEX ML.
Disaggregates model performance across individual source datasets (Enron, SpamAssassin, CEAS, Nazario, etc.)
to analyze cross-source generalization, domain shift, and source-specific error modes.
"""
from typing import Dict, Any, List, Optional
from collections import defaultdict
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from app.ml.version import TARGET_CLASSES, LABEL_TO_INT, INT_TO_LABEL


def evaluate_source_breakdown(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    source_datasets: List[str],
    classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes classification metrics broken down by individual source dataset.
    """
    class_names = classes or TARGET_CLASSES
    num_classes = len(class_names)
    y_pred = np.argmax(y_prob, axis=1)

    sources = np.array(source_datasets)
    unique_sources = sorted(list(set(sources)))

    results_by_source: Dict[str, Any] = {}
    source_f1_scores: List[float] = []

    for src in unique_sources:
        mask = sources == src
        src_y_true = y_true[mask]
        src_y_pred = y_pred[mask]
        src_y_prob = y_prob[mask]
        n_samples = int(np.sum(mask))

        if n_samples == 0:
            continue

        acc = float(round(accuracy_score(src_y_true, src_y_pred), 4))
        prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
            src_y_true, src_y_pred, average="macro", zero_division=0
        )
        source_f1_scores.append(f1_macro)

        # Class breakdown within this source
        class_counts: Dict[str, int] = {}
        for cidx, cname in enumerate(class_names):
            class_counts[cname] = int(np.sum(src_y_true == cidx))

        # Per-class performance within this source
        prec_c, rec_c, f1_c, sup_c = precision_recall_fscore_support(
            src_y_true, src_y_pred, labels=list(range(num_classes)), zero_division=0
        )

        per_class = {}
        for cidx, cname in enumerate(class_names):
            per_class[cname] = {
                "precision": float(round(prec_c[cidx], 4)),
                "recall": float(round(rec_c[cidx], 4)),
                "f1": float(round(f1_c[cidx], 4)),
                "support": int(sup_c[cidx]),
            }

        results_by_source[src] = {
            "sample_count": n_samples,
            "accuracy": acc,
            "macro_f1": float(round(f1_macro, 4)),
            "macro_precision": float(round(prec_macro, 4)),
            "macro_recall": float(round(rec_macro, 4)),
            "class_distribution": class_counts,
            "per_class": per_class,
        }

    # Summary diagnostics
    avg_source_f1 = float(round(float(np.mean(source_f1_scores)), 4)) if source_f1_scores else 0.0
    min_source_f1 = float(round(float(np.min(source_f1_scores)), 4)) if source_f1_scores else 0.0
    max_source_f1 = float(round(float(np.max(source_f1_scores)), 4)) if source_f1_scores else 0.0
    variance_source_f1 = float(round(float(np.var(source_f1_scores)), 4)) if source_f1_scores else 0.0

    # Identify most challenging source
    hardest_source = min(results_by_source.items(), key=lambda x: x[1]["macro_f1"])[0] if results_by_source else "N/A"

    return {
        "sources": results_by_source,
        "diagnostics": {
            "num_sources": len(unique_sources),
            "average_source_f1": avg_source_f1,
            "min_source_f1": min_source_f1,
            "max_source_f1": max_source_f1,
            "f1_variance": variance_source_f1,
            "hardest_source": hardest_source,
        },
    }


def format_source_evaluation_table(source_eval_dict: Dict[str, Any]) -> str:
    """Generates a Markdown table summarizing per-source metrics."""
    sources = source_eval_dict.get("sources", {})
    lines = [
        "| Source Dataset | Samples | Accuracy | Macro F1 | Phishing Recall | Phishing Prec |",
        "|:---------------|--------:|---------:|---------:|----------------:|--------------:|",
    ]
    for src, m in sorted(sources.items(), key=lambda x: x[1]["sample_count"], reverse=True):
        phish_rec = m["per_class"].get("phishing", {}).get("recall", 0.0)
        phish_prec = m["per_class"].get("phishing", {}).get("precision", 0.0)
        lines.append(
            f"| {src:<14} | {m['sample_count']:>7} | {m['accuracy']:>8.4f} | {m['macro_f1']:>8.4f} | "
            f"{phish_rec:>15.4f} | {phish_prec:>13.4f} |"
        )
    return "\n".join(lines)
