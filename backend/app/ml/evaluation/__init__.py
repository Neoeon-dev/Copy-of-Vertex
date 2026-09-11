"""
VERTEX ML Evaluation and Explainability Package.
Provides comprehensive multiclass metrics, calibration diagnostics, source-aware evaluation,
LOGO feature ablation, error analysis, and decision threshold sweeps.
"""
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

__all__ = [
    "evaluate_predictions",
    "calculate_expected_calibration_error",
    "calculate_multiclass_brier_score",
    "evaluate_source_breakdown",
    "format_source_evaluation_table",
    "run_feature_group_ablation",
    "format_ablation_table",
    "get_feature_group_map",
    "analyze_misclassifications",
    "analyze_phishing_thresholds",
    "format_threshold_table",
]
