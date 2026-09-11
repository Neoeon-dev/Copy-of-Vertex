"""
VERTEX ML Robustness and Diagnostics Package (Phase D2.1).
Exposes distribution comparisons, statistical drift, source fingerprinting,
evidence availability, binary threat diagnostics, feature group robustness,
and sensitivity analysis.
"""
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
    run_leave_one_source_out,
    run_threshold_shift_analysis,
    run_offline_perturbation_sensitivity,
)

__all__ = [
    "calculate_feature_summary",
    "calculate_psi",
    "calculate_feature_drift",
    "compute_distribution_comparison",
    "compute_drift_report",
    "train_source_classifier",
    "compute_threat_vs_source_correlation",
    "analyze_evidence_availability",
    "analyze_prediction_distributions",
    "analyze_holdout_confusion_patterns",
    "run_binary_threat_diagnostic",
    "run_phishing_vs_legitimate_diagnostic",
    "run_feature_subset_robustness_analysis",
    "run_leave_one_source_out",
    "run_threshold_shift_analysis",
    "run_offline_perturbation_sensitivity",
]
