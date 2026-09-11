"""
Comprehensive Evaluation and Metrics Engine for VERTEX ML.
Calculates multiclass classification metrics, calibration scores (Brier, log loss, ECE),
One-vs-Rest AUCs, and detailed threat-focused metrics.
"""
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    log_loss,
)
from sklearn.preprocessing import label_binarize

from app.ml.version import TARGET_CLASSES, LABEL_TO_INT, INT_TO_LABEL


def calculate_expected_calibration_error(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    n_bins: int = 10,
) -> float:
    """
    Computes multiclass Expected Calibration Error (ECE).
    Measures difference between predicted confidence and empirical accuracy.
    """
    confidences = np.max(y_prob, axis=1)
    predictions = np.argmax(y_prob, axis=1)
    accuracies = (predictions == y_true).astype(float)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n_samples = len(y_true)

    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = np.mean(in_bin)

        if prop_in_bin > 0:
            avg_accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_accuracy_in_bin - avg_confidence_in_bin) * prop_in_bin

    return float(round(ece, 4))


def calculate_multiclass_brier_score(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    num_classes: int = 3,
) -> float:
    """
    Computes multiclass Brier score: mean squared error over probability vectors.
    Range: [0, 2], where 0 is perfect probabilistic prediction.
    """
    y_one_hot = np.zeros_like(y_prob)
    for idx, label_idx in enumerate(y_true):
        if 0 <= label_idx < num_classes:
            y_one_hot[idx, label_idx] = 1.0

    brier = np.mean(np.sum((y_prob - y_one_hot) ** 2, axis=1))
    return float(round(brier, 4))


def evaluate_predictions(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes comprehensive evaluation metrics for multiclass predictions.
    """
    class_names = classes or TARGET_CLASSES
    num_classes = len(class_names)
    y_pred = np.argmax(y_prob, axis=1)

    # 1. Overall Metrics
    acc = accuracy_score(y_true, y_pred)
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # 2. Per-Class Metrics
    prec_per_class, rec_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_true, y_pred, labels=list(range(num_classes)), zero_division=0
    )

    per_class_dict = {}
    for idx, cname in enumerate(class_names):
        per_class_dict[cname] = {
            "precision": float(round(prec_per_class[idx], 4)),
            "recall": float(round(rec_per_class[idx], 4)),
            "f1": float(round(f1_per_class[idx], 4)),
            "support": int(support_per_class[idx]),
        }

    # 3. Probabilistic & Calibration Metrics
    brier = calculate_multiclass_brier_score(y_true, y_prob, num_classes=num_classes)
    loss = float(round(log_loss(y_true, y_prob, labels=list(range(num_classes))), 4))
    ece = calculate_expected_calibration_error(y_true, y_prob, n_bins=10)

    # 4. ROC-AUC and PR-AUC (One-vs-Rest)
    y_bin = label_binarize(y_true, classes=list(range(num_classes)))
    if num_classes == 2:
        y_bin = np.column_stack([1 - y_bin, y_bin])

    try:
        roc_auc_macro = float(round(roc_auc_score(y_bin, y_prob, multi_class="ovr", average="macro"), 4))
    except Exception:
        roc_auc_macro = 0.0

    pr_auc_per_class = {}
    roc_auc_per_class = {}
    for idx, cname in enumerate(class_names):
        try:
            p_curve, r_curve, _ = precision_recall_curve(y_bin[:, idx], y_prob[:, idx])
            pr_auc_per_class[cname] = float(round(auc(r_curve, p_curve), 4))
        except Exception:
            pr_auc_per_class[cname] = 0.0

        try:
            roc_auc_per_class[cname] = float(round(roc_auc_score(y_bin[:, idx], y_prob[:, idx]), 4))
        except Exception:
            roc_auc_per_class[cname] = 0.0

    pr_auc_macro = float(round(float(np.mean(list(pr_auc_per_class.values()))), 4))

    # 5. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes)))
    cm_norm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes)), normalize="true")

    cm_dict = {
        "classes": class_names,
        "counts": cm.tolist(),
        "normalized": np.round(cm_norm, 4).tolist(),
    }

    # 6. Focused Phishing Threat Metrics
    phishing_idx = LABEL_TO_INT.get("phishing", 2)
    phishing_metrics = {
        "precision": per_class_dict["phishing"]["precision"],
        "recall": per_class_dict["phishing"]["recall"],
        "f1": per_class_dict["phishing"]["f1"],
        "pr_auc": pr_auc_per_class.get("phishing", 0.0),
        "roc_auc": roc_auc_per_class.get("phishing", 0.0),
        "support": per_class_dict["phishing"]["support"],
    }

    return {
        "accuracy": float(round(acc, 4)),
        "macro_precision": float(round(prec_macro, 4)),
        "macro_recall": float(round(rec_macro, 4)),
        "macro_f1": float(round(f1_macro, 4)),
        "weighted_precision": float(round(prec_weighted, 4)),
        "weighted_recall": float(round(rec_weighted, 4)),
        "weighted_f1": float(round(f1_weighted, 4)),
        "brier_score": brier,
        "log_loss": loss,
        "expected_calibration_error": ece,
        "roc_auc_macro": roc_auc_macro,
        "pr_auc_macro": pr_auc_macro,
        "per_class": per_class_dict,
        "pr_auc_per_class": pr_auc_per_class,
        "roc_auc_per_class": roc_auc_per_class,
        "phishing_focus": phishing_metrics,
        "confusion_matrix": cm_dict,
    }
