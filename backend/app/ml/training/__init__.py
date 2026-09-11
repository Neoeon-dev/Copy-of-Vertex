"""
VERTEX ML Model Training Package.
Exposes trainers, calibrators, and CLI orchestrators for forensic tabular modeling.
"""
from app.ml.training.trainer_logistic import train_logistic_baseline, LogisticTrainingResult
from app.ml.training.trainer_lightgbm import (
    train_lightgbm,
    compare_weighting_strategies,
    LightGBMTrainingResult,
    extract_feature_importances,
)
from app.ml.training.calibrator import calibrate_and_select, CalibrationComparisonResult

__all__ = [
    "train_logistic_baseline",
    "LogisticTrainingResult",
    "train_lightgbm",
    "compare_weighting_strategies",
    "LightGBMTrainingResult",
    "extract_feature_importances",
    "calibrate_and_select",
    "CalibrationComparisonResult",
]
