"""
Text representation robustness, subject/body ablation, and D2.1 failure reproduction suite for Phase D3.
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional, Callable
import numpy as np
import pandas as pd
from app.ml.semantic.preprocessor import EmailTextPreprocessor
from app.ml.semantic.evaluator import evaluate_predictions


def run_subject_body_ablation(
    subjects: List[str],
    bodies: List[str],
    y_true: np.ndarray,
    predict_fn: Callable[[List[str]], np.ndarray],
) -> Dict[str, Any]:
    """
    Evaluates model performance under:
    A. Subject only
    B. Body only
    C. Subject + Body
    """
    modes = ["both", "subject_only", "body_only"]
    results = {}

    for mode in modes:
        p = EmailTextPreprocessor(part_mode=mode)
        formatted_texts = [p.format_email(s, b) for s, b in zip(subjects, bodies)]
        probs = predict_fn(formatted_texts)
        metrics = evaluate_predictions(y_true, probs)
        results[mode] = {
            "accuracy": metrics["accuracy"],
            "macro_f1": metrics["macro_f1"],
            "phishing_precision": metrics["phishing_metrics"]["precision"],
            "phishing_recall": metrics["phishing_metrics"]["recall"],
            "phishing_f1": metrics["phishing_metrics"]["f1"],
            "phishing_pr_auc": metrics["phishing_metrics"]["pr_auc"],
        }

    return results


def run_text_perturbation_tests(
    subjects: List[str],
    bodies: List[str],
    baseline_probs: np.ndarray,
    predict_fn: Callable[[List[str]], np.ndarray],
) -> Dict[str, Any]:
    """
    Measures prediction flip rates and probability shifts under offline text perturbations:
    1. URL replacement ([URL]) vs Strip URLs vs Raw URLs
    2. HTML stripping vs Raw HTML
    3. Whitespace normalization vs Raw whitespace
    """
    baseline_preds = np.argmax(baseline_probs, axis=1)
    baseline_phish_probs = baseline_probs[:, 2]

    perturbations = {
        "strip_urls": EmailTextPreprocessor(url_mode="strip"),
        "raw_urls": EmailTextPreprocessor(url_mode="keep"),
        "raw_html": EmailTextPreprocessor(strip_html=False),
        "raw_whitespace": EmailTextPreprocessor(normalize_whitespace=False),
        "lowercase_all": EmailTextPreprocessor(lowercase=True),
    }

    results = {}
    for p_name, prep in perturbations.items():
        perturbed_texts = [prep.format_email(s, b) for s, b in zip(subjects, bodies)]
        pert_probs = predict_fn(perturbed_texts)
        pert_preds = np.argmax(pert_probs, axis=1)
        pert_phish_probs = pert_probs[:, 2]

        flip_rate = float(np.mean(baseline_preds != pert_preds))
        phish_prob_delta = float(np.mean(pert_phish_probs - baseline_phish_probs))
        abs_prob_delta = float(np.mean(np.abs(pert_phish_probs - baseline_phish_probs)))

        results[p_name] = {
            "prediction_flip_rate": round(flip_rate * 100.0, 2),
            "mean_phishing_prob_delta": round(phish_prob_delta, 4),
            "mean_abs_prob_delta": round(abs_prob_delta, 4),
        }

    return results


def test_d2_1_failure_reproduction(
    df: pd.DataFrame,
    predict_fn: Callable[[List[str]], np.ndarray],
) -> Dict[str, Any]:
    """
    Explicitly tests D3 on the scenario that broke D2:
    short (< 25 words), headerless, URL-free emails.
    """
    word_counts = np.array([len(str(b).split()) for b in df["body"]])
    has_headers = df["has_headers"].fillna(0).astype(int).values if "has_headers" in df else np.zeros(len(df))
    url_count = df["url_count"].fillna(0).astype(int).values if "url_count" in df else np.zeros(len(df))

    # Mask: short body, zero headers, zero URLs
    target_mask = (word_counts <= 25) & (has_headers == 0) & (url_count == 0)
    count = int(np.sum(target_mask))

    if count == 0:
        return {"reproduced": False, "reason": "No samples matching short+headerless+url_free criteria found"}

    sub_df = df[target_mask]
    p = EmailTextPreprocessor()
    formatted_texts = [p.format_email(s, b) for s, b in zip(sub_df["subject"], sub_df["body"])]
    probs = predict_fn(formatted_texts)
    
    label_col = sub_df["normalized_label"]
    label_map = {"legitimate": 0, "spam": 1, "phishing": 2}
    y_true = np.array([label_map.get(str(lbl), 0) for lbl in label_col])

    metrics = evaluate_predictions(y_true, probs)
    return {
        "matching_sample_count": count,
        "class_distribution": {
            "legitimate": int(np.sum(y_true == 0)),
            "spam": int(np.sum(y_true == 1)),
            "phishing": int(np.sum(y_true == 2)),
        },
        "accuracy": metrics["accuracy"],
        "macro_f1": metrics["macro_f1"],
        "phishing_precision": metrics["phishing_metrics"]["precision"],
        "phishing_recall": metrics["phishing_metrics"]["recall"],
        "phishing_f1": metrics["phishing_metrics"]["f1"],
        "phishing_pr_auc": metrics["phishing_metrics"]["pr_auc"],
        "confusion_matrix": metrics["confusion_matrix"],
    }
