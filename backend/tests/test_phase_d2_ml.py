"""
Phase D2 Automated Test Suite for VERTEX Forensic Tabular ML.
Tests loaders, baseline trainer, LightGBM trainer, calibrator, metrics, LOGO ablation,
source evaluation, error analysis, threshold analysis, inference service, and artifacts.
"""
import os
import json
import pytest
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from typing import Dict, Any

from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES, LABEL_TO_INT, INT_TO_LABEL
from app.ml.preprocessing.tabular_loader import TabularDataset, load_tabular_parquet
from app.ml.evaluation.metrics import (
    evaluate_predictions,
    calculate_expected_calibration_error,
    calculate_multiclass_brier_score,
)
from app.ml.evaluation.source_eval import (
    evaluate_source_breakdown,
    format_source_evaluation_table,
)
from app.ml.evaluation.ablation import (
    run_feature_group_ablation,
    format_ablation_table,
    get_feature_group_map,
)
from app.ml.evaluation.error_analysis import (
    analyze_misclassifications,
)
from app.ml.evaluation.threshold_analysis import (
    analyze_phishing_thresholds,
    format_threshold_table,
)
from app.ml.training.trainer_logistic import train_logistic_baseline, LogisticTrainingResult
from app.ml.training.trainer_lightgbm import (
    train_lightgbm,
    compare_weighting_strategies,
    extract_feature_importances,
    LightGBMTrainingResult,
)
from app.ml.training.calibrator import calibrate_and_select, CalibrationComparisonResult
from app.ml.models.forensic_service import (
    ForensicTabularService,
    get_forensic_service,
    ForensicPrediction,
)
from app.data.schema import CanonicalEmailRecord
from app.features.registry import get_feature_names


@pytest.fixture
def synthetic_features():
    """Generates synthetic feature matrices and datasets for unit testing."""
    np.random.seed(42)
    feature_names = get_feature_names()
    n_features = len(feature_names)
    n_samples_tr = 120
    n_samples_val = 60

    X_tr = np.random.randn(n_samples_tr, n_features).astype(np.float32)
    y_tr = np.random.choice([0, 1, 2], size=n_samples_tr).astype(np.int64)

    X_val = np.random.randn(n_samples_val, n_features).astype(np.float32)
    y_val = np.random.choice([0, 1, 2], size=n_samples_val).astype(np.int64)

    sources_tr = ["source_alpha"] * 60 + ["source_beta"] * 60
    sources_val = ["source_alpha"] * 30 + ["source_beta"] * 30

    train_ds = TabularDataset(
        X=X_tr,
        y=y_tr,
        feature_names=feature_names,
        record_ids=[f"rec_tr_{i}" for i in range(n_samples_tr)],
        source_datasets=sources_tr,
        threat_types=["clean" if y == 0 else "generic_phish" for y in y_tr],
        raw_evidence_available=[1.0] * n_samples_tr,
        normalized_labels=[INT_TO_LABEL[y] for y in y_tr],
    )

    val_ds = TabularDataset(
        X=X_val,
        y=y_val,
        feature_names=feature_names,
        record_ids=[f"rec_val_{i}" for i in range(n_samples_val)],
        source_datasets=sources_val,
        threat_types=["clean" if y == 0 else "generic_phish" for y in y_val],
        raw_evidence_available=[1.0] * n_samples_val,
        normalized_labels=[INT_TO_LABEL[y] for y in y_val],
    )

    return train_ds, val_ds


def test_metrics_evaluation_perfect():
    """Tests evaluate_predictions with perfect predictions."""
    y_true = np.array([0, 1, 2, 0, 1, 2])
    y_prob = np.array([
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
    ])
    metrics = evaluate_predictions(y_true, y_prob)
    assert metrics["accuracy"] == 1.0
    assert metrics["macro_f1"] == 1.0
    assert metrics["brier_score"] == 0.0
    assert metrics["expected_calibration_error"] == 0.0
    assert metrics["phishing_focus"]["f1"] == 1.0


def test_ece_calculation():
    """Tests expected calibration error on calibrated vs miscalibrated predictions."""
    # Perfectly calibrated confidence equals empirical accuracy
    y_true = np.array([0, 0, 1, 1])
    y_prob = np.array([
        [0.5, 0.5, 0.0],
        [0.5, 0.5, 0.0],
        [0.5, 0.5, 0.0],
        [0.5, 0.5, 0.0],
    ])
    ece = calculate_expected_calibration_error(y_true, y_prob, n_bins=5)
    assert isinstance(ece, float)
    assert ece >= 0.0


def test_multiclass_brier_score():
    """Tests Brier score computation."""
    y_true = np.array([0, 1])
    # Total error: (1-0)^2 + 1 = 2 per sample
    y_wrong = np.array([[0.0, 1.0, 0.0], [1.0, 0.0, 0.0]])
    brier = calculate_multiclass_brier_score(y_true, y_wrong, num_classes=3)
    assert brier == 2.0


def test_tabular_dataset_leakage_rejection(tmp_path):
    """Ensures load_tabular_parquet raises ValueError if forbidden target key is passed in features."""
    parquet_file = str(tmp_path / "leaked.parquet")
    fnames = get_feature_names()
    data = {f: [1.0] for f in fnames}
    data["normalized_label"] = ["phishing"]
    table = pa.Table.from_pydict(data)
    pq.write_table(table, parquet_file)

    with pytest.raises(ValueError, match="Target leakage"):
        load_tabular_parquet(parquet_file, feature_names=["normalized_label"] + fnames[:5])


def test_logistic_baseline_trainer(synthetic_features, tmp_path):
    """Tests Logistic Regression baseline trainer end-to-end."""
    train_ds, val_ds = synthetic_features
    res = train_logistic_baseline(train_ds, val_ds, max_iter=50)

    assert isinstance(res, LogisticTrainingResult)
    assert "accuracy" in res.train_metrics
    assert "accuracy" in res.val_metrics
    assert res.training_duration_seconds > 0
    assert "phishing" in res.feature_coefficients

    # Test serialization
    out_dir = str(tmp_path / "logistic")
    res.save(out_dir)
    assert os.path.exists(os.path.join(out_dir, "logistic_baseline_pipeline.pkl"))
    assert os.path.exists(os.path.join(out_dir, "logistic_baseline_metrics.json"))
    assert os.path.exists(os.path.join(out_dir, "logistic_coefficients.json"))


def test_lightgbm_trainer_and_importances(synthetic_features, tmp_path):
    """Tests LightGBM classifier trainer, early stopping, and feature importances."""
    train_ds, val_ds = synthetic_features
    res = train_lightgbm(train_ds, val_ds, n_estimators=20, early_stopping_rounds=5)

    assert isinstance(res, LightGBMTrainingResult)
    assert res.best_iteration >= 1
    assert len(res.feature_importances_gain) == len(train_ds.feature_names)
    assert len(res.feature_importances_split) == len(train_ds.feature_names)

    # Test serialization
    out_dir = str(tmp_path / "lgbm")
    res.save(out_dir)
    assert os.path.exists(os.path.join(out_dir, "lightgbm_model.pkl"))
    assert os.path.exists(os.path.join(out_dir, "feature_importances.json"))
    assert os.path.exists(os.path.join(out_dir, "lightgbm_metrics.json"))


def test_lightgbm_weighting_comparison(synthetic_features):
    """Tests compare_weighting_strategies on synthetic datasets."""
    train_ds, val_ds = synthetic_features
    winner, comp = compare_weighting_strategies(train_ds, val_ds)

    assert comp["chosen_strategy"] in ["natural", "balanced"]
    assert "natural" in comp and "balanced" in comp
    assert isinstance(winner, LightGBMTrainingResult)


def test_calibrator_selection(synthetic_features, tmp_path):
    """Tests probability calibration search on LightGBM predictions."""
    train_ds, val_ds = synthetic_features
    lgbm_res = train_lightgbm(train_ds, val_ds, n_estimators=20)
    cal_res = calibrate_and_select(lgbm_res.model, val_ds, candidate_methods=["sigmoid", "isotonic"])

    assert isinstance(cal_res, CalibrationComparisonResult)
    assert cal_res.chosen_method in ["uncalibrated", "sigmoid", "isotonic"]
    assert "uncalibrated" in cal_res.comparison_metrics

    # Test serialization
    out_dir = str(tmp_path / "cal")
    cal_res.save(out_dir)
    assert os.path.exists(os.path.join(out_dir, "calibrated_model.pkl"))
    assert os.path.exists(os.path.join(out_dir, "calibration_report.json"))


def test_source_breakdown_evaluation():
    """Tests source-aware evaluation breakdown and formatted markdown table."""
    y_true = np.array([0, 1, 2, 0, 1, 2])
    y_prob = np.array([
        [0.8, 0.1, 0.1],
        [0.1, 0.8, 0.1],
        [0.1, 0.1, 0.8],
        [0.7, 0.2, 0.1],
        [0.2, 0.7, 0.1],
        [0.1, 0.2, 0.7],
    ])
    sources = ["source_a", "source_a", "source_a", "source_b", "source_b", "source_b"]
    res = evaluate_source_breakdown(y_true, y_prob, sources)

    assert "source_a" in res["sources"]
    assert "source_b" in res["sources"]
    assert res["diagnostics"]["num_sources"] == 2
    assert res["diagnostics"]["average_source_f1"] == 1.0

    table_md = format_source_evaluation_table(res)
    assert "| Source Dataset |" in table_md
    assert "source_a" in table_md


def test_ablation_engine(synthetic_features):
    """Tests feature group ablation on synthetic data."""
    train_ds, val_ds = synthetic_features
    res = run_feature_group_ablation(train_ds, val_ds, n_estimators=10)

    assert "baseline" in res
    assert "groups" in res
    assert len(res["rankings"]) > 0

    tbl = format_ablation_table(res)
    assert "Baseline" in tbl
    assert "| Rank |" in tbl


def test_error_analysis():
    """Tests forensic error analysis diagnostic engine."""
    y_true = np.array([0, 2, 1, 2])
    # 0 -> 2 (FP phish), 2 -> 0 (FN phish), 1 -> 2 (Spam to phish), 2 -> 2 (Correct)
    y_prob = np.array([
        [0.1, 0.1, 0.8],
        [0.8, 0.1, 0.1],
        [0.1, 0.2, 0.7],
        [0.1, 0.1, 0.8],
    ])
    feature_names = ["auth_spf_pass", "url_count"]
    X = np.array([[0.0, 1.0], [1.0, 0.0], [0.0, 2.0], [1.0, 1.0]])

    res = analyze_misclassifications(y_true, y_prob, feature_names, X)
    assert res["summary"]["total_samples"] == 4
    assert res["summary"]["total_errors"] == 3
    assert res["summary"]["false_positives_phishing"] == 1
    assert res["summary"]["false_negatives_phishing_as_legit"] == 1
    assert res["summary"]["spam_confused_as_phishing"] == 1
    assert len(res["top_cases"]["highest_confidence_false_positives"]) == 1


def test_threshold_analysis():
    """Tests phishing decision threshold sweep and recommendation generation."""
    y_true = np.array([0, 1, 2, 2, 0, 2])
    y_prob = np.array([
        [0.8, 0.1, 0.1],
        [0.2, 0.7, 0.1],
        [0.1, 0.1, 0.8],
        [0.2, 0.2, 0.6],
        [0.6, 0.3, 0.1],
        [0.1, 0.0, 0.9],
    ])
    res = analyze_phishing_thresholds(y_true, y_prob)

    assert len(res["sweep"]) > 0
    assert "balanced_f1" in res["recommendations"]
    assert "high_recall_soc_triage" in res["recommendations"]
    assert "low_fpr_blocking" in res["recommendations"]

    table_md = format_threshold_table(res)
    assert "| Threshold |" in table_md


def test_forensic_service_inference():
    """Tests production ForensicTabularService inference across input types."""
    svc = get_forensic_service()
    assert svc.model is not None
    assert len(svc.feature_names) == 125

    # 1. Feature Dict Inference
    pred = svc.predict_features({"url_count": 5.0, "bec_urgency_words_count": 3.0})
    assert isinstance(pred, ForensicPrediction)
    assert pred.predicted_label in TARGET_CLASSES
    assert 0.0 <= pred.confidence <= 1.0
    assert 0.0 <= pred.risk_score <= 1.0
    assert sum(pred.probabilities.values()) == pytest.approx(1.0, abs=0.01)

    # 2. CanonicalEmailRecord Inference
    rec = CanonicalEmailRecord(
        record_id="t_001",
        source_dataset="test",
        source_record_id="s_001",
        original_label="phish",
        normalized_label="phishing",
        threat_type="credential_harvesting",
        subject="URGENT: Verify password now",
        body="Please click https://verify.fake-phish.com to confirm your password.",
        sender="admin@fake.com",
    )
    pred_rec = svc.predict_record(rec)
    assert isinstance(pred_rec, ForensicPrediction)
    assert pred_rec.predicted_label in TARGET_CLASSES

    # 3. Raw bytes inference
    raw_email = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Hi\r\n\r\nHello there!"
    pred_raw = svc.predict_raw_email(raw_email)
    assert isinstance(pred_raw, ForensicPrediction)


def test_forensic_service_uninitialized_fallback():
    """Tests graceful fallback when service is initialized with an empty dir."""
    svc = ForensicTabularService(model_dir="/non/existent/dir")
    assert svc.model is None
    pred = svc.predict_features({})
    assert pred.predicted_label == "legitimate"
    assert pred.is_calibrated is False


def test_model_artifacts_and_card_exist():
    """Verifies all Phase D2 model artifacts and MODEL_CARD.md exist."""
    model_dir = "models/forensic/v1"
    if not os.path.exists(model_dir):
        model_dir = "../models/forensic/v1"

    assert os.path.exists(model_dir), f"Directory {model_dir} must exist"
    assert os.path.exists(os.path.join(model_dir, "calibrated_model.pkl"))
    assert os.path.exists(os.path.join(model_dir, "lightgbm_model.pkl"))
    assert os.path.exists(os.path.join(model_dir, "metadata.json"))
    assert os.path.exists(os.path.join(model_dir, "MODEL_CARD.md"))

    # Verify model card contains required sections
    with open(os.path.join(model_dir, "MODEL_CARD.md"), "r", encoding="utf-8") as f:
        card_content = f.read()

    assert "VERTEX Forensic Tabular Model Card" in card_content
    assert "Test Set Performance" in card_content
    assert "Holdout Independent Evaluation" in card_content
    assert "Feature Group Ablation Summary" in card_content
    assert "Source-Aware Breakdown" in card_content
    assert "Recommended Operational Thresholds" in card_content


def test_tabular_loader_nan_inf_detection(tmp_path):
    """Tests load_tabular_parquet raises ValueError on NaN or Inf in feature columns."""
    parquet_file = str(tmp_path / "nan.parquet")
    fnames = get_feature_names()
    data = {f: [1.0] for f in fnames}
    data[fnames[0]] = [float("nan")]
    data["normalized_label"] = ["phishing"]
    table = pa.Table.from_pydict(data)
    pq.write_table(table, parquet_file)

    with pytest.raises(ValueError, match="NaN values detected"):
        load_tabular_parquet(parquet_file)


def test_forensic_prediction_to_dict():
    """Tests ForensicPrediction dictionary representation."""
    pred = ForensicPrediction(
        predicted_label="phishing",
        confidence=0.95432,
        probabilities={"legitimate": 0.01, "spam": 0.04, "phishing": 0.95},
        risk_score=0.968,
        top_contributing_features=[{"feature": "url_count", "value": 4.0}],
        model_version="1.0.0",
        is_calibrated=True,
        features_used_count=125,
        latency_ms=12.345,
    )
    d = pred.to_dict()
    assert d["predicted_label"] == "phishing"
    assert d["confidence"] == 0.9543
    assert d["is_calibrated"] is True
    assert d["features_used_count"] == 125
    assert len(d["top_contributing_features"]) == 1


def test_model_card_generator_function():
    """Tests generate_model_card_markdown function with sample inputs."""
    from app.ml.training.cli import generate_model_card_markdown

    meta = {"model_version": "1.0.0", "champion_model": "LightGBM", "calibration_method": "sigmoid"}
    val_m = {"accuracy": 0.91, "macro_f1": 0.90, "phishing_focus": {"f1": 0.89, "pr_auc": 0.94}}
    test_m = {"accuracy": 0.92, "macro_f1": 0.91, "weighted_f1": 0.92, "phishing_focus": {"precision": 0.89, "recall": 0.90, "f1": 0.895, "pr_auc": 0.96, "roc_auc": 0.98, "support": 1000}, "per_class": {"legitimate": {"support": 2000}, "spam": {"support": 1000}}}
    holdout_m = {"accuracy": 0.85, "macro_f1": 0.84, "phishing_focus": {"precision": 0.84, "recall": 0.86, "f1": 0.85, "pr_auc": 0.91, "support": 1000}, "per_class": {"legitimate": {"support": 1000}}}
    abl_summary = {"baseline": {"num_features": 125, "macro_f1": 0.90, "phishing_pr_auc": 0.94}, "rankings": [{"rank": 1, "group": "url_signals", "num_features": 12, "f1_drop": 0.02, "pr_auc_drop": 0.015}]}
    src_summary = {"sources": {"enron": {"sample_count": 500, "accuracy": 0.95, "macro_f1": 0.94, "per_class": {"phishing": {"recall": 0.93, "precision": 0.92}}}}}
    thresh_summary = {"recommendations": {"balanced_f1": {"threshold": 0.50}, "high_recall_soc_triage": {"threshold": 0.15}, "low_fpr_blocking": {"threshold": 0.90}}}

    card = generate_model_card_markdown(meta, val_m, test_m, holdout_m, abl_summary, src_summary, thresh_summary)
    assert "# VERTEX Forensic Tabular Model Card" in card
    assert "Holdout Independent Evaluation" in card
    assert "0.8500" in card

