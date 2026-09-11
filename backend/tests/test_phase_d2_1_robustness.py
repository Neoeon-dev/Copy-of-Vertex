"""
Automated Test Suite for Phase D2.1 (Forensic ML Robustness & Domain-Shift Investigation).
Tests distribution calculation, PSI and drift statistics, source fingerprinting,
evidence availability, binary diagnostic models, threshold shifts, and report files.
"""
import os
import json
import pytest
import numpy as np

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.diagnostics.drift import (
    calculate_feature_summary,
    calculate_psi,
    calculate_feature_drift,
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
    run_threshold_shift_analysis,
    run_offline_perturbation_sensitivity,
    evaluate_binary_metrics,
)
from app.ml.diagnostics.runner import json_dump_safe
from app.features.registry import get_feature_names


@pytest.fixture
def synthetic_diagnostic_data():
    """Generates synthetic datasets for fast, self-contained unit testing."""
    np.random.seed(42)
    feature_names = get_feature_names()
    n_feats = len(feature_names)
    n_samples_tr = 90
    n_samples_val = 30
    n_samples_ho = 40

    X_tr = np.random.randn(n_samples_tr, n_feats).astype(np.float32)
    y_tr = np.random.choice([0, 1, 2], size=n_samples_tr).astype(np.int64)

    X_val = np.random.randn(n_samples_val, n_feats).astype(np.float32)
    y_val = np.random.choice([0, 1, 2], size=n_samples_val).astype(np.int64)

    # Shift holdout distribution on first 5 features
    X_ho = np.random.randn(n_samples_ho, n_feats).astype(np.float32)
    X_ho[:, :5] += 3.0
    y_ho = np.random.choice([0, 2], size=n_samples_ho).astype(np.int64)

    train_ds = TabularDataset(
        X=X_tr, y=y_tr, feature_names=feature_names,
        record_ids=[f"tr_{i}" for i in range(n_samples_tr)],
        source_datasets=["src_a"] * 45 + ["src_b"] * 45,
        threat_types=["clean"] * n_samples_tr,
        raw_evidence_available=[1.0] * n_samples_tr,
        normalized_labels=["legitimate"] * n_samples_tr,
    )
    val_ds = TabularDataset(
        X=X_val, y=y_val, feature_names=feature_names,
        record_ids=[f"val_{i}" for i in range(n_samples_val)],
        source_datasets=["src_a"] * 15 + ["src_b"] * 15,
        threat_types=["clean"] * n_samples_val,
        raw_evidence_available=[1.0] * n_samples_val,
        normalized_labels=["legitimate"] * n_samples_val,
    )
    holdout_ds = TabularDataset(
        X=X_ho, y=y_ho, feature_names=feature_names,
        record_ids=[f"ho_{i}" for i in range(n_samples_ho)],
        source_datasets=["src_c"] * n_samples_ho,
        threat_types=["clean"] * n_samples_ho,
        raw_evidence_available=[0.0] * n_samples_ho,
        normalized_labels=["legitimate"] * n_samples_ho,
    )
    return train_ds, val_ds, holdout_ds


def test_calculate_feature_summary():
    """Tests summary statistics and missing rate."""
    arr = np.array([-1.0, 0.0, 2.0, 4.0, 6.0])
    summary = calculate_feature_summary(arr)
    assert summary["missing_rate"] == 0.2
    assert summary["zero_rate"] == 0.2
    assert summary["min"] == -1.0
    assert summary["max"] == 6.0
    assert summary["unique_count"] == 5


def test_calculate_psi_stable_and_drift():
    """Tests PSI bounds: low for identical distribution, high for shifted."""
    np.random.seed(42)
    a = np.random.randn(1000)
    b = np.random.randn(1000)
    psi_stable = calculate_psi(a, b)
    assert psi_stable < 0.1, f"Expected low PSI, got {psi_stable}"

    c = np.random.randn(1000) + 3.0
    psi_drift = calculate_psi(a, c)
    assert psi_drift > 0.25, f"Expected high PSI, got {psi_drift}"


def test_calculate_feature_drift():
    """Tests feature drift calculation including KS and Wasserstein."""
    a = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
    b = np.array([10.0, 12.0, 14.0, 16.0, 18.0])
    res = calculate_feature_drift(a, b, "test_feature")
    assert res["psi"] > 0.25
    assert res["drift_level"] == "high"
    assert res["wasserstein"] > 5.0


def test_compute_distribution_comparison(synthetic_diagnostic_data):
    """Tests distribution comparison across splits."""
    tr, val, ho = synthetic_diagnostic_data
    comp_dict, rows = compute_distribution_comparison({"train": tr, "holdout": ho})
    assert len(rows) == len(tr.feature_names)
    assert "train_mean" in rows[0]
    assert "holdout_mean" in rows[0]


def test_compute_drift_report(synthetic_diagnostic_data):
    """Tests drift report and group summary."""
    tr, val, ho = synthetic_diagnostic_data
    drift_dict, rows = compute_drift_report(tr, val, val, ho)
    assert len(drift_dict["top_20_holdout_drift"]) == 20
    assert "group_summary" in drift_dict
    assert len(drift_dict["group_summary"]) > 0


def test_source_classifier(synthetic_diagnostic_data):
    """Tests diagnostic source-dataset classifier."""
    tr, val, ho = synthetic_diagnostic_data
    res = train_source_classifier(tr, val, val, n_estimators=10)
    assert res["num_sources"] == 2
    assert 0.0 <= res["test_accuracy"] <= 1.0
    assert len(res["top_source_fingerprint_features"]) > 0


def test_threat_vs_source_correlation(synthetic_diagnostic_data):
    """Tests ANOVA F-statistic threat vs source ratio."""
    tr, _, _ = synthetic_diagnostic_data
    res = compute_threat_vs_source_correlation(tr)
    assert len(res) == len(tr.feature_names)
    assert "f_statistic_threat" in res[0]
    assert "source_to_threat_ratio" in res[0]


def test_analyze_evidence_availability(synthetic_diagnostic_data):
    """Tests evidence availability indicators."""
    tr, val, ho = synthetic_diagnostic_data
    rep = analyze_evidence_availability({"train": tr, "holdout": ho})
    assert rep["train"]["raw_rfc822_available"] == 1.0
    assert rep["holdout"]["raw_rfc822_available"] == 0.0


def test_binary_threat_diagnostic(synthetic_diagnostic_data):
    """Tests binary threat diagnostic."""
    tr, val, ho = synthetic_diagnostic_data
    res = run_binary_threat_diagnostic(tr, val, val, ho)
    assert "test_metrics" in res
    assert "holdout_metrics" in res
    assert "f1" in res["test_metrics"]


def test_phishing_vs_legitimate_diagnostic(synthetic_diagnostic_data):
    """Tests phishing vs legitimate diagnostic."""
    tr, val, ho = synthetic_diagnostic_data
    res = run_phishing_vs_legitimate_diagnostic(tr, val, val, ho)
    assert "test_metrics" in res
    assert "holdout_metrics" in res
    assert 0.0 <= res["test_metrics"]["accuracy"] <= 1.0


def test_json_dump_safe(tmp_path):
    """Tests numpy-safe json serialization."""
    out_file = str(tmp_path / "safe.json")
    obj = {
        "np_int": np.int64(42),
        "np_float": np.float64(3.1415),
        "np_array": np.array([1, 2, 3]),
    }
    json_dump_safe(obj, out_file)
    with open(out_file, "r") as f:
        loaded = json.load(f)
    assert loaded["np_int"] == 42
    assert abs(loaded["np_float"] - 3.1415) < 1e-4
    assert loaded["np_array"] == [1, 2, 3]


def test_d2_1_generated_reports_exist():
    """Verifies that all Phase D2.1 reports were generated in reports/d2_1."""
    reports_dir = "reports/d2_1"
    if not os.path.exists(reports_dir):
        reports_dir = "../reports/d2_1"

    assert os.path.exists(reports_dir), f"Directory {reports_dir} must exist"

    expected_files = [
        "feature_distribution_comparison.json",
        "feature_distribution_comparison.csv",
        "feature_drift_report.json",
        "feature_drift_report.csv",
        "group_drift_report.json",
        "source_fingerprint_report.json",
        "evidence_availability_report.json",
        "prediction_distribution_report.json",
        "confusion_analysis.json",
        "binary_threat_results.json",
        "phishing_legitimate_results.json",
        "feature_robustness_results.json",
        "source_holdout_results.json",
        "calibration_shift_report.json",
        "threshold_shift_report.json",
        "sensitivity_results.json",
        "training_corpus_composition.json",
    ]

    for fname in expected_files:
        p = os.path.join(reports_dir, fname)
        assert os.path.exists(p), f"Expected artifact {fname} missing in {reports_dir}"
        assert os.path.getsize(p) > 0, f"Artifact {fname} must not be empty"
