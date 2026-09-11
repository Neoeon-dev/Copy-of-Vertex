"""
Master Diagnostic Runner for Phase D2.1 (Forensic ML Robustness & Domain-Shift Investigation).
Executes all 22 investigation steps, computes statistical distributions and drift,
evaluates diagnostic threat models, and serializes comprehensive artifacts into reports/d2_1/.
"""
from typing import Dict, Any, List, Optional
import os
import csv
import json
import time
import joblib
import numpy as np

from app.ml.preprocessing.tabular_loader import load_tabular_parquet, TabularDataset
from app.ml.diagnostics.drift import (
    compute_distribution_comparison,
    compute_drift_report,
)
from app.ml.diagnostics.source_fingerprint import (
    train_source_classifier,
    compute_threat_vs_source_correlation,
)
from app.ml.diagnostics.evidence_analysis import (
    analyze_evidence_availability,
    analyze_prediction_distributions,
    analyze_holdout_confusion_patterns,
)
from app.ml.diagnostics.robustness_experiments import (
    run_binary_threat_diagnostic,
    run_phishing_vs_legitimate_diagnostic,
    run_feature_subset_robustness_analysis,
    run_leave_one_source_out,
    run_threshold_shift_analysis,
    run_offline_perturbation_sensitivity,
)
from app.ml.evaluation.metrics import (
    calculate_expected_calibration_error,
    calculate_multiclass_brier_score,
)
from sklearn.metrics import log_loss


def resolve_path(rel_path: str) -> str:
    """Finds path whether running from repo root or backend."""
    candidates = [
        os.path.abspath(rel_path),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..", rel_path)),
        os.path.abspath(os.path.join("..", rel_path)),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return os.path.abspath(rel_path)


def json_dump_safe(obj: Any, filepath: str) -> None:
    """Safely serializes nested dictionaries containing numpy types to JSON."""
    def _default(o):
        if isinstance(o, (np.integer, int)):
            return int(o)
        elif isinstance(o, (np.floating, float)):
            return float(o)
        elif isinstance(o, np.ndarray):
            return o.tolist()
        return str(o)

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=_default)


def write_csv_report(filepath: str, rows: List[Dict[str, Any]]) -> None:
    """Helper to write list of dicts to CSV."""
    if not rows:
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_phase_d2_1_investigation() -> Dict[str, Any]:
    """Runs the complete Phase D2.1 investigation."""
    print("=" * 70)
    print("VERTEX PHASE D2.1 — FORENSIC ML ROBUSTNESS & DOMAIN-SHIFT INVESTIGATION")
    print("=" * 70)

    # 1. Paths and Baseline Reproduction
    print("\n[Baseline] Loading Datasets and D2 Champion Model...")
    train_path = resolve_path("data/processed/features/train_features.parquet")
    val_path = resolve_path("data/processed/features/validation_features.parquet")
    test_path = resolve_path("data/processed/features/test_features.parquet")
    holdout_path = resolve_path("data/processed/features/holdout_independent_features.parquet")

    model_path = resolve_path("models/forensic/v1/calibrated_model.pkl")
    meta_path = resolve_path("models/forensic/v1/metadata.json")
    importances_path = resolve_path("models/forensic/v1/feature_importances.json")

    reports_dir = resolve_path("reports/d2_1")
    os.makedirs(reports_dir, exist_ok=True)

    train_ds = load_tabular_parquet(train_path)
    val_ds = load_tabular_parquet(val_path)
    test_ds = load_tabular_parquet(test_path)
    holdout_ds = load_tabular_parquet(holdout_path)

    d2_model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        d2_meta = json.load(f)
    with open(importances_path, "r", encoding="utf-8") as f:
        d2_importances = json.load(f).get("gain", {})

    print(f"  Train:   {train_ds.num_samples:,} samples | Val: {val_ds.num_samples:,} samples")
    print(f"  Test:    {test_ds.num_samples:,} samples | Holdout: {holdout_ds.num_samples:,} samples")
    print(f"  D2 Baseline Verified: Test Acc={d2_meta['test_metrics']['accuracy']} | Holdout Acc={d2_meta['holdout_metrics']['accuracy']}")

    splits_map = {
        "train": train_ds,
        "validation": val_ds,
        "test": test_ds,
        "holdout": holdout_ds,
    }

    # Step 1: Dataset Distributions
    print("\n[Step 1/22] Calculating Feature Distribution Comparisons...")
    dist_dict, dist_csv_rows = compute_distribution_comparison(splits_map)
    json_dump_safe(dist_dict, os.path.join(reports_dir, "feature_distribution_comparison.json"))
    write_csv_report(os.path.join(reports_dir, "feature_distribution_comparison.csv"), dist_csv_rows)
    print("  Saved feature_distribution_comparison.json and .csv")

    # Step 2, 3, 4: Feature Drift, Rankings & Group Drift
    print("\n[Steps 2-4/22] Calculating Statistical Drift (PSI, KS, Wasserstein)...")
    drift_dict, drift_csv_rows = compute_drift_report(train_ds, val_ds, test_ds, holdout_ds)
    json_dump_safe(drift_dict, os.path.join(reports_dir, "feature_drift_report.json"))
    write_csv_report(os.path.join(reports_dir, "feature_drift_report.csv"), drift_csv_rows)
    json_dump_safe(drift_dict["group_summary"], os.path.join(reports_dir, "group_drift_report.json"))

    top_drifted = drift_dict["top_20_holdout_drift"]
    print(f"  Top 3 Drifted Features: {top_drifted[0]['feature']} (PSI={top_drifted[0]['holdout_psi']}), {top_drifted[1]['feature']} (PSI={top_drifted[1]['holdout_psi']}), {top_drifted[2]['feature']} (PSI={top_drifted[2]['holdout_psi']})")

    # Step 5 & 6: Source Fingerprint Test & Threat vs Source Correlation
    print("\n[Steps 5-6/22] Training Source-Dataset Classifier & Correlation Ratios...")
    src_clf_res = train_source_classifier(train_ds, val_ds, test_ds)
    print(f"  Source Classifier Val Accuracy:  {src_clf_res['val_accuracy']*100:.2f}%")
    print(f"  Source Classifier Test Accuracy: {src_clf_res['test_accuracy']*100:.2f}%")
    print(f"  Top Source Fingerprints: {[f['feature'] for f in src_clf_res['top_source_fingerprint_features'][:3]]}")

    threat_vs_source_res = compute_threat_vs_source_correlation(train_ds)
    src_fingerprint_payload = {
        "source_classifier": src_clf_res,
        "threat_vs_source_correlation": threat_vs_source_res,
    }
    json_dump_safe(src_fingerprint_payload, os.path.join(reports_dir, "source_fingerprint_report.json"))

    # Step 7: Available-Evidence Analysis
    print("\n[Step 7/22] Analyzing Evidence Availability Across Splits...")
    evidence_res = analyze_evidence_availability(splits_map)
    json_dump_safe(evidence_res, os.path.join(reports_dir, "evidence_availability_report.json"))
    print(f"  Raw RFC822 Availability: Train={evidence_res['train']['raw_rfc822_available']*100:.1f}% vs Holdout={evidence_res['holdout']['raw_rfc822_available']*100:.1f}%")
    print(f"  Headers Available:       Train={evidence_res['train']['headers_available']*100:.1f}% vs Holdout={evidence_res['holdout']['headers_available']*100:.1f}%")

    # Step 8: Prediction Distribution Analysis
    print("\n[Step 8/22] Analyzing Prediction Distributions on Test vs Holdout...")
    pred_dist_res = analyze_prediction_distributions(d2_model, test_ds, holdout_ds)
    json_dump_safe(pred_dist_res, os.path.join(reports_dir, "prediction_distribution_report.json"))
    print(f"  Holdout Legit Mean Probs:  P(legit)={pred_dist_res['holdout']['per_true_class']['legitimate']['mean_p_legitimate']} | P(phish)={pred_dist_res['holdout']['per_true_class']['legitimate']['mean_p_phishing']}")
    print(f"  Holdout Phish Mean Probs:  P(phish)={pred_dist_res['holdout']['per_true_class']['phishing']['mean_p_phishing']} | P(legit)={pred_dist_res['holdout']['per_true_class']['phishing']['mean_p_legitimate']}")

    # Step 9: Holdout Confusion Analysis
    print("\n[Step 9/22] Dissecting Holdout Confusion Quadrants and Case Studies...")
    confusion_res = analyze_holdout_confusion_patterns(d2_model, holdout_ds)
    json_dump_safe(confusion_res, os.path.join(reports_dir, "confusion_analysis.json"))
    quads = confusion_res["confusion_quadrants"]
    print(f"  Legit -> Phishing: {quads['legitimate_predicted_as_phishing']['count']} ({quads['legitimate_predicted_as_phishing']['pct_of_class']}%)")
    print(f"  Phishing Correct:  {quads['phishing_correctly_predicted']['count']} ({quads['phishing_correctly_predicted']['pct_of_class']}%)")

    # Step 10: Binary Threat Test (Legit vs Threat)
    print("\n[Step 10/22] Running Binary Threat Diagnostic (Legitimate vs Threat)...")
    binary_threat_res = run_binary_threat_diagnostic(train_ds, val_ds, test_ds, holdout_ds)
    json_dump_safe(binary_threat_res, os.path.join(reports_dir, "binary_threat_results.json"))
    print(f"  Binary Threat Test F1:    {binary_threat_res['test_metrics']['f1']:.4f} (PR-AUC: {binary_threat_res['test_metrics']['pr_auc']:.4f})")
    print(f"  Binary Threat Holdout F1: {binary_threat_res['holdout_metrics']['f1']:.4f} (PR-AUC: {binary_threat_res['holdout_metrics']['pr_auc']:.4f})")

    # Step 11: Phishing vs Legitimate Diagnostic (Excluding Spam)
    print("\n[Step 11/22] Running Phishing vs Legitimate Diagnostic (Excluding Spam)...")
    phish_legit_res = run_phishing_vs_legitimate_diagnostic(train_ds, val_ds, test_ds, holdout_ds)
    json_dump_safe(phish_legit_res, os.path.join(reports_dir, "phishing_legitimate_results.json"))
    print(f"  Phish vs Legit Test F1:    {phish_legit_res['test_metrics']['f1']:.4f} (PR-AUC: {phish_legit_res['test_metrics']['pr_auc']:.4f})")
    print(f"  Phish vs Legit Holdout F1: {phish_legit_res['holdout_metrics']['f1']:.4f} (PR-AUC: {phish_legit_res['holdout_metrics']['pr_auc']:.4f})")

    # Step 12 & 13: Feature Group & Subset Robustness Analysis
    print("\n[Steps 12-13/22] Analyzing Feature Group and Subset Generalization Robustness...")
    holdout_psi_map = {r["feature"]: r["holdout_psi"] for r in drift_csv_rows}
    subset_res = run_feature_subset_robustness_analysis(
        train_ds, val_ds, test_ds, holdout_ds, holdout_psi_map, d2_importances
    )
    json_dump_safe(subset_res, os.path.join(reports_dir, "feature_robustness_results.json"))
    for s_name, s_data in subset_res.items():
        print(f"  Subset {s_name:<26}: Test F1={s_data['test_macro_f1']:.4f} | Holdout F1={s_data['holdout_macro_f1']:.4f} | Gap={s_data['generalization_gap_f1']:.4f}")

    # Step 14: Training Corpus Composition
    print("\n[Step 14/22] Analyzing Training Corpus Composition...")
    from collections import Counter
    src_counts = dict(Counter(train_ds.source_datasets))
    src_threat_dist = {}
    for src in sorted(src_counts.keys()):
        mask = np.array(train_ds.source_datasets) == src
        src_labels = train_ds.y[mask]
        src_threat_dist[src] = {
            "total": int(np.sum(mask)),
            "pct_of_train": float(round((np.sum(mask) / train_ds.num_samples) * 100, 2)),
            "legitimate": int(np.sum(src_labels == 0)),
            "spam": int(np.sum(src_labels == 1)),
            "phishing": int(np.sum(src_labels == 2)),
        }
    json_dump_safe(src_threat_dist, os.path.join(reports_dir, "training_corpus_composition.json"))

    # Step 15: Source Holdout (LOSO)
    print("\n[Step 15/22] Performing Leave-One-Source-Out (LOSO) Diagnostics...")
    loso_res = run_leave_one_source_out(train_ds, val_ds)
    json_dump_safe(loso_res, os.path.join(reports_dir, "source_holdout_results.json"))
    for src, m in loso_res.items():
        print(f"  Held-Out {src:<28}: Accuracy={m['accuracy']:.4f} | Macro F1={m['macro_f1']:.4f}")

    # Step 16: Calibration Under Shift
    print("\n[Step 16/22] Comparing Probability Calibration Under Distribution Shift...")
    test_probs = d2_model.predict_proba(test_ds.X)
    ho_probs = d2_model.predict_proba(holdout_ds.X)

    test_brier = calculate_multiclass_brier_score(test_ds.y, test_probs, num_classes=3)
    ho_brier = calculate_multiclass_brier_score(holdout_ds.y, ho_probs, num_classes=3)

    test_ece = calculate_expected_calibration_error(test_ds.y, test_probs)
    ho_ece = calculate_expected_calibration_error(holdout_ds.y, ho_probs)

    test_ll = float(round(log_loss(test_ds.y, test_probs, labels=[0, 1, 2]), 4))
    ho_ll = float(round(log_loss(holdout_ds.y, ho_probs, labels=[0, 1, 2]), 4))

    cal_shift = {
        "test": {"brier_score": test_brier, "ece": test_ece, "log_loss": test_ll},
        "holdout": {"brier_score": ho_brier, "ece": ho_ece, "log_loss": ho_ll},
        "brier_inflation": float(round(ho_brier - test_brier, 4)),
        "ece_inflation": float(round(ho_ece - test_ece, 4)),
    }
    json_dump_safe(cal_shift, os.path.join(reports_dir, "calibration_shift_report.json"))
    print(f"  Test Brier={test_brier} vs Holdout Brier={ho_brier} | Test ECE={test_ece} vs Holdout ECE={ho_ece}")

    # Step 17: Threshold Robustness
    print("\n[Step 17/22] Analyzing Threshold Robustness Across 0.05 - 0.95...")
    thresh_res = run_threshold_shift_analysis(d2_model, test_ds, holdout_ds)
    json_dump_safe(thresh_res, os.path.join(reports_dir, "threshold_shift_report.json"))
    for p in thresh_res["threshold_shifts"]:
        print(f"  Threshold {p['threshold']:^4}: Test Prec={p['test']['precision']:.4f} -> Holdout Prec={p['holdout']['precision']:.4f} (FPR={p['holdout']['fpr']:.4f})")

    # Step 19 & 20: Perturbation Sensitivity Analysis
    print("\n[Steps 19-20/22] Running Feature Perturbation Sensitivity Analysis...")
    sens_res = run_offline_perturbation_sensitivity(d2_model, test_ds)
    json_dump_safe(sens_res, os.path.join(reports_dir, "sensitivity_results.json"))
    for p_name, p_data in sens_res.items():
        print(f"  Perturbation {p_name:<20}: Flip Rate={p_data['prediction_flip_rate']*100:.1f}% | Phish Delta={p_data['mean_phishing_probability_shift']:+.4f}")

    print("\n" + "=" * 70)
    print("PHASE D2.1 INVESTIGATION COMPLETED SUCCESSFULLY!")
    print(f"All 16 artifact reports generated in: {reports_dir}")
    print("=" * 70)

    return {
        "drift": drift_dict,
        "source_fingerprint": src_fingerprint_payload,
        "evidence_availability": evidence_res,
        "prediction_distributions": pred_dist_res,
        "confusion_patterns": confusion_res,
        "binary_threat": binary_threat_res,
        "phishing_legitimate": phish_legit_res,
        "subset_robustness": subset_res,
        "source_holdout": loso_res,
        "calibration_shift": cal_shift,
        "threshold_shift": thresh_res,
        "sensitivity": sens_res,
        "training_corpus_composition": src_threat_dist,
    }


if __name__ == "__main__":
    run_phase_d2_1_investigation()
