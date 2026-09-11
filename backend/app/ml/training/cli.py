"""
VERTEX Forensic Tabular ML CLI Orchestrator (Phase D2).
Orchestrates baseline training, LightGBM training, calibration selection,
feature group ablation, source evaluation, error analysis, threshold sweep,
artifact serialization, and final one-time holdout evaluation.
"""
from typing import Dict, Any, Optional, List
import argparse
import os
import sys
import json
import time
import shutil
import joblib
import numpy as np

from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES
from app.ml.preprocessing.tabular_loader import load_tabular_parquet, TabularDataset
from app.ml.training.trainer_logistic import train_logistic_baseline, LogisticTrainingResult
from app.ml.training.trainer_lightgbm import (
    train_lightgbm,
    compare_weighting_strategies,
    LightGBMTrainingResult,
    extract_feature_importances,
)
from app.ml.training.calibrator import calibrate_and_select, CalibrationComparisonResult
from app.ml.evaluation.metrics import evaluate_predictions
from app.ml.evaluation.source_eval import evaluate_source_breakdown, format_source_evaluation_table
from app.ml.evaluation.ablation import run_feature_group_ablation, format_ablation_table
from app.ml.evaluation.error_analysis import analyze_misclassifications
from app.ml.evaluation.threshold_analysis import analyze_phishing_thresholds, format_threshold_table


def find_data_path(rel_path: str) -> str:
    """Resolves data paths across working directory and backend directory."""
    candidates = [
        os.path.abspath(rel_path),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..", rel_path)),
        os.path.abspath(os.path.join("..", rel_path)),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return os.path.abspath(rel_path)


def generate_model_card_markdown(
    metadata: Dict[str, Any],
    val_metrics: Dict[str, Any],
    test_metrics: Dict[str, Any],
    holdout_metrics: Optional[Dict[str, Any]],
    ablation_summary: Dict[str, Any],
    source_summary: Dict[str, Any],
    threshold_summary: Dict[str, Any],
) -> str:
    """Generates standard Model Card markdown document following ML governance guidelines."""
    champion_type = metadata.get("champion_model", "LightGBM")
    cal_method = metadata.get("calibration_method", "calibrated")
    
    lines = [
        f"# VERTEX Forensic Tabular Model Card (v{metadata.get('model_version', '1.0.0')})",
        "",
        "## Model Overview",
        f"- **Model Type:** Multiclass LightGBM Classifier ({champion_type})",
        f"- **Calibration:** {cal_method.capitalize()} probability scaling",
        f"- **Version:** `{metadata.get('model_version', '1.0.0')}`",
        f"- **Input Dimensions:** 125 canonical forensic features (11 forensic groups)",
        "- **Target Classes:** `0: legitimate`, `1: spam`, `2: phishing`",
        f"- **Date Built:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "## Intended Use & Forensic Scope",
        "- **Primary Purpose:** Explainable forensic threat classification of enterprise and institutional emails.",
        "- **Core Capability:** Differentiates high-consequence targeted phishing / BEC threats from commercial bulk spam and benign traffic.",
        "- **Out of Scope:** Does not rely on remote external reputation lookups at inference time; all 125 features are computed deterministically from MIME RFC822 artifacts and parsed evidence.",
        "",
        "## Validation Performance",
        f"- **Accuracy:** `{val_metrics.get('accuracy', 0.0):.4f}`",
        f"- **Macro F1:** `{val_metrics.get('macro_f1', 0.0):.4f}`",
        f"- **Phishing F1:** `{val_metrics.get('phishing_focus', {}).get('f1', 0.0):.4f}`",
        f"- **Phishing PR-AUC:** `{val_metrics.get('phishing_focus', {}).get('pr_auc', 0.0):.4f}`",
        f"- **Brier Score:** `{val_metrics.get('brier_score', 0.0):.4f}`",
        f"- **Expected Calibration Error (ECE):** `{val_metrics.get('expected_calibration_error', 0.0):.4f}`",
        "",
        "## Test Set Performance (Unseen Test Split)",
        f"- **Test Samples:** `{test_metrics.get('phishing_focus', {}).get('support', 0) + test_metrics.get('per_class', {}).get('legitimate', {}).get('support', 0) + test_metrics.get('per_class', {}).get('spam', {}).get('support', 0)}`",
        f"- **Accuracy:** `{test_metrics.get('accuracy', 0.0):.4f}`",
        f"- **Macro F1:** `{test_metrics.get('macro_f1', 0.0):.4f}`",
        f"- **Weighted F1:** `{test_metrics.get('weighted_f1', 0.0):.4f}`",
        f"- **Phishing Precision:** `{test_metrics.get('phishing_focus', {}).get('precision', 0.0):.4f}`",
        f"- **Phishing Recall:** `{test_metrics.get('phishing_focus', {}).get('recall', 0.0):.4f}`",
        f"- **Phishing F1:** `{test_metrics.get('phishing_focus', {}).get('f1', 0.0):.4f}`",
        f"- **Phishing PR-AUC:** `{test_metrics.get('phishing_focus', {}).get('pr_auc', 0.0):.4f}`",
        f"- **Phishing ROC-AUC:** `{test_metrics.get('phishing_focus', {}).get('roc_auc', 0.0):.4f}`",
        f"- **Test Brier Score:** `{test_metrics.get('brier_score', 0.0):.4f}`",
        f"- **Test Log Loss:** `{test_metrics.get('log_loss', 0.0):.4f}`",
        f"- **Test ECE:** `{test_metrics.get('expected_calibration_error', 0.0):.4f}`",
        "",
    ]

    if holdout_metrics:
        lines.extend([
            "## Holdout Independent Evaluation (Evaluated Strictly Once)",
            "> [!IMPORTANT]",
            "> Evaluated strictly once after all model selection and calibration decisions were finalized.",
            f"- **Holdout Samples:** `{holdout_metrics.get('phishing_focus', {}).get('support', 0) + holdout_metrics.get('per_class', {}).get('legitimate', {}).get('support', 0)}`",
            f"- **Holdout Accuracy:** `{holdout_metrics.get('accuracy', 0.0):.4f}`",
            f"- **Holdout Macro F1:** `{holdout_metrics.get('macro_f1', 0.0):.4f}`",
            f"- **Holdout Phishing Recall:** `{holdout_metrics.get('phishing_focus', {}).get('recall', 0.0):.4f}`",
            f"- **Holdout Phishing Precision:** `{holdout_metrics.get('phishing_focus', {}).get('precision', 0.0):.4f}`",
            f"- **Holdout Phishing F1:** `{holdout_metrics.get('phishing_focus', {}).get('f1', 0.0):.4f}`",
            f"- **Holdout Phishing PR-AUC:** `{holdout_metrics.get('phishing_focus', {}).get('pr_auc', 0.0):.4f}`",
            f"- **Holdout Brier Score:** `{holdout_metrics.get('brier_score', 0.0):.4f}`",
            f"- **Holdout ECE:** `{holdout_metrics.get('expected_calibration_error', 0.0):.4f}`",
            "",
        ])

    lines.extend([
        "## Feature Group Ablation Summary",
        format_ablation_table(ablation_summary),
        "",
        "## Source-Aware Breakdown (Test Set)",
        format_source_evaluation_table(source_summary),
        "",
        "## Recommended Operational Thresholds",
        "- **Balanced Triage (F1 optimal):** Threshold = "
        f"`{threshold_summary.get('recommendations', {}).get('balanced_f1', {}).get('threshold', 0.5):.2f}`",
        "- **High-Recall SOC Queue:** Threshold = "
        f"`{threshold_summary.get('recommendations', {}).get('high_recall_soc_triage', {}).get('threshold', 0.35):.2f}`",
        "- **Autonomous Inline Block (FPR < 0.5%):** Threshold = "
        f"`{threshold_summary.get('recommendations', {}).get('low_fpr_blocking', {}).get('threshold', 0.70):.2f}`",
        "",
    ])

    return "\n".join(lines)


def run_full_phase_d2_pipeline(
    train_parquet: str,
    val_parquet: str,
    test_parquet: str,
    holdout_parquet: str,
    output_model_dir: str,
    artifacts_dir: str,
    manifests_dir: str,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Executes the complete Phase D2 pipeline.
    """
    print("=" * 70)
    print("VERTEX PHASE D2 — TABULAR ML TRAINING & RIGOROUS EVALUATION PIPELINE")
    print("=" * 70)

    # 1. Load Data
    print("\n[Step 1/11] Loading Datasets...")
    train_ds = load_tabular_parquet(train_parquet)
    val_ds = load_tabular_parquet(val_parquet)
    print(f"  Loaded Train: {train_ds.num_samples:,} samples, {train_ds.num_features} features")
    print(f"  Loaded Val:   {val_ds.num_samples:,} samples, {val_ds.num_features} features")

    # 2. Train Logistic Regression Baseline
    print("\n[Step 2/11] Training Multiclass Logistic Regression Baseline...")
    logistic_res = train_logistic_baseline(train_ds, val_ds, random_state=random_state)
    print(f"  Logistic Baseline Val Accuracy: {logistic_res.val_metrics['accuracy']:.4f}")
    print(f"  Logistic Baseline Val Macro F1: {logistic_res.val_metrics['macro_f1']:.4f}")
    print(f"  Logistic Baseline Val Phish PR-AUC: {logistic_res.val_metrics['phishing_focus']['pr_auc']:.4f}")
    print(f"  Logistic Baseline Val Brier: {logistic_res.val_metrics['brier_score']:.4f}")

    # 3. Train LightGBM Model & Compare Weighting Strategies
    print("\n[Step 3/11] Training LightGBM Classifiers (Natural vs Balanced)...")
    lgbm_winner, weighting_comp = compare_weighting_strategies(train_ds, val_ds, random_state=random_state)
    print(f"  Weighting Comparison: Natural F1={weighting_comp['natural']['macro_f1']:.4f} vs Balanced F1={weighting_comp['balanced']['macro_f1']:.4f}")
    print(f"  Chosen Strategy: {weighting_comp['chosen_strategy']} (Best Iteration: {lgbm_winner.best_iteration})")
    print(f"  LightGBM Val Accuracy: {lgbm_winner.val_metrics['accuracy']:.4f}")
    print(f"  LightGBM Val Macro F1: {lgbm_winner.val_metrics['macro_f1']:.4f}")
    print(f"  LightGBM Val Phish PR-AUC: {lgbm_winner.val_metrics['phishing_focus']['pr_auc']:.4f}")
    print(f"  LightGBM Val Brier: {lgbm_winner.val_metrics['brier_score']:.4f}")

    # 4. Calibration Search on Validation Set
    print("\n[Step 4/11] Performing Probability Calibration Selection on Validation Set...")
    cal_res = calibrate_and_select(lgbm_winner.model, val_ds, candidate_methods=["sigmoid", "isotonic"])
    print(f"  Calibration Champion: {cal_res.chosen_method.upper()}")
    print(f"  Selection Rationale: {cal_res.selection_rationale}")
    for m_name, m_stats in cal_res.comparison_metrics.items():
        if "error" not in m_stats:
            print(f"    - {m_name:<13}: Brier={m_stats['brier_score']:.4f}, ECE={m_stats['expected_calibration_error']:.4f}, Macro F1={m_stats['macro_f1']:.4f}")

    # 5. Feature Group Ablation (LOGO)
    print("\n[Step 5/11] Conducting 11-Group Leave-One-Group-Out (LOGO) Ablation...")
    ablation_res = run_feature_group_ablation(train_ds, val_ds, n_estimators=300, random_state=random_state)
    print("  Top 3 Most Critical Feature Groups (Highest Macro F1 Drop):")
    for r in ablation_res["rankings"][:3]:
        print(f"    Rank {r['rank']}: {r['group']} (-{r['f1_drop']:.4f} F1, -{r['pr_auc_drop']:.4f} PR-AUC)")

    # 6. Champion Model Selection
    print("\n[Step 6/11] Selecting Final Champion Model & Pipeline...")
    champion_model = cal_res.calibrated_model
    champion_calibrated = (cal_res.chosen_method != "uncalibrated")

    # 7. Unseen Test Set Evaluation
    print("\n[Step 7/11] Evaluating Champion on Test Split (test_features.parquet)...")
    test_ds = load_tabular_parquet(test_parquet)
    print(f"  Loaded Test: {test_ds.num_samples:,} samples")
    test_probs = champion_model.predict_proba(test_ds.X)
    test_metrics = evaluate_predictions(test_ds.y, test_probs, classes=TARGET_CLASSES)
    print(f"  Test Accuracy:     {test_metrics['accuracy']:.4f}")
    print(f"  Test Macro F1:     {test_metrics['macro_f1']:.4f}")
    print(f"  Test Weighted F1:  {test_metrics['weighted_f1']:.4f}")
    print(f"  Test Phish Prec:   {test_metrics['phishing_focus']['precision']:.4f}")
    print(f"  Test Phish Recall: {test_metrics['phishing_focus']['recall']:.4f}")
    print(f"  Test Phish F1:     {test_metrics['phishing_focus']['f1']:.4f}")
    print(f"  Test Phish PR-AUC: {test_metrics['phishing_focus']['pr_auc']:.4f}")
    print(f"  Test Brier Score:  {test_metrics['brier_score']:.4f}")
    print(f"  Test ECE:          {test_metrics['expected_calibration_error']:.4f}")

    # 8. Source Evaluation & Error Analysis on Test Split
    print("\n[Step 8/11] Running Source-Aware Evaluation & Diagnostic Error Analysis...")
    source_eval_res = evaluate_source_breakdown(test_ds.y, test_probs, test_ds.source_datasets)
    print(f"  Evaluated across {source_eval_res['diagnostics']['num_sources']} source datasets.")
    print(f"  Average Source F1: {source_eval_res['diagnostics']['average_source_f1']:.4f} (Hardest: {source_eval_res['diagnostics']['hardest_source']})")

    error_analysis_res = analyze_misclassifications(
        y_true=test_ds.y,
        y_prob=test_probs,
        feature_names=test_ds.feature_names,
        X=test_ds.X,
        record_ids=test_ds.record_ids,
        source_datasets=test_ds.source_datasets,
        raw_evidence=test_ds.raw_evidence_available,
    )
    print(f"  Total Test Misclassifications: {error_analysis_res['summary']['total_errors']} / {error_analysis_res['summary']['total_samples']} ({error_analysis_res['summary']['error_rate']*100:.2f}%)")
    print(f"  False Positives (Phishing): {error_analysis_res['summary']['false_positives_phishing']}")
    print(f"  False Negatives (Phishing): {error_analysis_res['summary']['false_negatives_phishing_as_legit']} (as legit) + {error_analysis_res['summary']['false_negatives_phishing_as_spam']} (as spam)")

    # 9. Decision Threshold Analysis
    print("\n[Step 9/11] Performing Phishing Decision Threshold Sweep...")
    threshold_res = analyze_phishing_thresholds(test_ds.y, test_probs)
    rec_bal = threshold_res["recommendations"]["balanced_f1"]
    print(f"  Optimal F1 Threshold: {rec_bal['threshold']:.2f} (Prec: {rec_bal['metrics']['precision']:.4f}, Rec: {rec_bal['metrics']['recall']:.4f}, F1: {rec_bal['metrics']['f1']:.4f})")
    rec_soc = threshold_res["recommendations"]["high_recall_soc_triage"]
    print(f"  High-Recall Threshold: {rec_soc['threshold']:.2f} (Rec: {rec_soc['metrics']['recall']:.4f}, Prec: {rec_soc['metrics']['precision']:.4f})")
    rec_blk = threshold_res["recommendations"]["low_fpr_blocking"]
    print(f"  Low-FPR Blocking Threshold: {rec_blk['threshold']:.2f} (FPR: {rec_blk['metrics']['fpr']:.4f}, Prec: {rec_blk['metrics']['precision']:.4f})")

    # 10. Save Artifacts to models/forensic/v1 and backend/app/ml/artifacts
    print(f"\n[Step 10/11] Serializing Champion Artifacts to {output_model_dir}...")
    os.makedirs(output_model_dir, exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)

    # Save models
    lgbm_winner.save(output_model_dir)
    cal_res.save(output_model_dir)
    logistic_res.save(output_model_dir)

    # Copy to backend artifacts directory as well
    for fname in ["calibrated_model.pkl", "lightgbm_model.pkl", "feature_importances.json"]:
        src = os.path.join(output_model_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(artifacts_dir, fname))

    # 11. Final One-Time Holdout Evaluation
    print("\n[Step 11/11] Evaluating on Independent Holdout (holdout_independent_features.parquet) STRICTLY ONCE...")
    holdout_ds = load_tabular_parquet(holdout_parquet)
    print(f"  Loaded Holdout: {holdout_ds.num_samples:,} samples")
    holdout_probs = champion_model.predict_proba(holdout_ds.X)
    holdout_metrics = evaluate_predictions(holdout_ds.y, holdout_probs, classes=TARGET_CLASSES)
    print(f"  Holdout Accuracy:     {holdout_metrics['accuracy']:.4f}")
    print(f"  Holdout Macro F1:     {holdout_metrics['macro_f1']:.4f}")
    print(f"  Holdout Phish Prec:   {holdout_metrics['phishing_focus']['precision']:.4f}")
    print(f"  Holdout Phish Recall: {holdout_metrics['phishing_focus']['recall']:.4f}")
    print(f"  Holdout Phish F1:     {holdout_metrics['phishing_focus']['f1']:.4f}")
    print(f"  Holdout Phish PR-AUC: {holdout_metrics['phishing_focus']['pr_auc']:.4f}")
    print(f"  Holdout Brier Score:  {holdout_metrics['brier_score']:.4f}")
    print(f"  Holdout ECE:          {holdout_metrics['expected_calibration_error']:.4f}")

    # Build and Save Comprehensive Metadata
    metadata_payload = {
        "model_version": FORENSIC_MODEL_VERSION,
        "date_trained": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "champion_model": "LightGBM",
        "class_weight_strategy": lgbm_winner.class_weight_strategy,
        "best_iteration": lgbm_winner.best_iteration,
        "calibration_method": cal_res.chosen_method,
        "calibration_rationale": cal_res.selection_rationale,
        "input_features_count": len(train_ds.feature_names),
        "target_classes": TARGET_CLASSES,
        "validation_metrics": lgbm_winner.val_metrics,
        "test_metrics": test_metrics,
        "holdout_metrics": holdout_metrics,
        "baseline_logistic_val_metrics": logistic_res.val_metrics,
    }

    meta_path = os.path.join(output_model_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata_payload, f, indent=2)
    shutil.copy2(meta_path, os.path.join(artifacts_dir, "metadata.json"))

    # Generate Model Card
    model_card_text = generate_model_card_markdown(
        metadata=metadata_payload,
        val_metrics=lgbm_winner.val_metrics,
        test_metrics=test_metrics,
        holdout_metrics=holdout_metrics,
        ablation_summary=ablation_res,
        source_summary=source_eval_res,
        threshold_summary=threshold_res,
    )
    model_card_path = os.path.join(output_model_dir, "MODEL_CARD.md")
    with open(model_card_path, "w", encoding="utf-8") as f:
        f.write(model_card_text)

    # Save Master Pipeline Results to data/manifests
    os.makedirs(manifests_dir, exist_ok=True)
    full_pipeline_results = {
        "metadata": metadata_payload,
        "logistic_baseline": {
            "hyperparameters": logistic_res.hyperparameters,
            "train_metrics": logistic_res.train_metrics,
            "val_metrics": logistic_res.val_metrics,
        },
        "lightgbm_training": {
            "hyperparameters": lgbm_winner.hyperparameters,
            "weighting_comparison": weighting_comp,
            "train_metrics": lgbm_winner.train_metrics,
            "val_metrics": lgbm_winner.val_metrics,
        },
        "calibration": {
            "chosen_method": cal_res.chosen_method,
            "selection_rationale": cal_res.selection_rationale,
            "comparison": cal_res.comparison_metrics,
        },
        "ablation": ablation_res,
        "test_evaluation": test_metrics,
        "source_evaluation": source_eval_res,
        "error_analysis": error_analysis_res,
        "threshold_analysis": threshold_res,
        "holdout_evaluation": holdout_metrics,
    }

    manifest_path = os.path.join(manifests_dir, "phase_d2_pipeline_results.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(full_pipeline_results, f, indent=2)
    print(f"\nSaved full results to {manifest_path}")
    print(f"Saved Model Card to {model_card_path}")

    print("\n" + "=" * 70)
    print("PHASE D2 PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 70)

    return full_pipeline_results


def main():
    parser = argparse.ArgumentParser(description="VERTEX Phase D2 Tabular ML Pipeline CLI")
    parser.add_argument("--full-pipeline", action="store_true", help="Run end-to-end training and evaluation")
    parser.add_argument("--train-baseline", action="store_true", help="Train baseline Logistic Regression only")
    parser.add_argument("--train-lightgbm", action="store_true", help="Train LightGBM only")
    parser.add_argument("--calibrate", action="store_true", help="Run calibration selection only")
    parser.add_argument("--ablation", action="store_true", help="Run feature group ablation only")
    parser.add_argument("--evaluate-test", action="store_true", help="Evaluate model on test split only")
    parser.add_argument("--evaluate-holdout", action="store_true", help="Evaluate model on holdout split only")
    
    args = parser.parse_args()

    train_path = find_data_path("data/processed/features/train_features.parquet")
    val_path = find_data_path("data/processed/features/validation_features.parquet")
    test_path = find_data_path("data/processed/features/test_features.parquet")
    holdout_path = find_data_path("data/processed/features/holdout_independent_features.parquet")

    output_model_dir = find_data_path("models/forensic/v1")
    artifacts_dir = find_data_path("backend/app/ml/artifacts")
    manifests_dir = find_data_path("data/manifests")

    # Default to full-pipeline if no specific flag is given
    if args.full_pipeline or not any([
        args.train_baseline, args.train_lightgbm, args.calibrate,
        args.ablation, args.evaluate_test, args.evaluate_holdout
    ]):
        run_full_phase_d2_pipeline(
            train_parquet=train_path,
            val_parquet=val_path,
            test_parquet=test_path,
            holdout_parquet=holdout_path,
            output_model_dir=output_model_dir,
            artifacts_dir=artifacts_dir,
            manifests_dir=manifests_dir,
        )


if __name__ == "__main__":
    main()
