"""
Probability Calibration Engine for VERTEX Forensic Tabular ML.
Compares Uncalibrated vs Sigmoid (Platt Scaling) vs Isotonic Regression on the validation split.
Computes Brier score, Log Loss, and Expected Calibration Error (ECE) to select the optimal calibrator.
"""
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
import os
import json
import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
try:
    from sklearn.calibration import FrozenEstimator
except ImportError:
    FrozenEstimator = None

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.evaluation.metrics import evaluate_predictions
from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES


@dataclass
class CalibrationComparisonResult:
    """Container holding calibrated models, comparative metrics, and the selected champion."""
    chosen_method: str  # 'uncalibrated' | 'sigmoid' | 'isotonic'
    calibrated_model: Any
    comparison_metrics: Dict[str, Dict[str, Any]]
    selection_rationale: str
    model_version: str = FORENSIC_MODEL_VERSION

    def save(self, output_dir: str) -> None:
        """Serializes calibrated model artifact and calibration comparison metrics."""
        os.makedirs(output_dir, exist_ok=True)

        # 1. Calibrated model artifact
        joblib.dump(self.calibrated_model, os.path.join(output_dir, "calibrated_model.pkl"))

        # 2. Calibration comparison metrics
        payload = {
            "model_version": self.model_version,
            "chosen_method": self.chosen_method,
            "selection_rationale": self.selection_rationale,
            "comparison": self.comparison_metrics,
        }
        with open(os.path.join(output_dir, "calibration_report.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


def fit_calibrator(base_model: Any, X_val: np.ndarray, y_val: np.ndarray, method: str) -> Any:
    """Fits CalibratedClassifierCV on prefit base model using specified method."""
    if FrozenEstimator is not None:
        calibrator = CalibratedClassifierCV(
            estimator=FrozenEstimator(base_model),
            method=method,
        )
    else:
        calibrator = CalibratedClassifierCV(
            estimator=base_model,
            method=method,
            cv="prefit",
        )
    calibrator.fit(X_val, y_val)
    return calibrator


def calibrate_and_select(
    base_model: Any,
    val_ds: TabularDataset,
    candidate_methods: Optional[List[str]] = None,
) -> CalibrationComparisonResult:
    """
    Evaluates Uncalibrated, Sigmoid, and Isotonic calibration on validation dataset.
    Measures Brier score, Log Loss, and ECE to choose the optimal calibrator.
    """
    if candidate_methods is None:
        candidate_methods = ["sigmoid", "isotonic"]

    comparison: Dict[str, Dict[str, Any]] = {}
    models_dict: Dict[str, Any] = {}

    # 1. Evaluate Uncalibrated baseline
    raw_probs = base_model.predict_proba(val_ds.X)
    uncal_metrics = evaluate_predictions(val_ds.y, raw_probs, classes=TARGET_CLASSES)
    comparison["uncalibrated"] = {
        "brier_score": uncal_metrics["brier_score"],
        "log_loss": uncal_metrics["log_loss"],
        "expected_calibration_error": uncal_metrics["expected_calibration_error"],
        "macro_f1": uncal_metrics["macro_f1"],
        "phishing_f1": uncal_metrics["phishing_focus"]["f1"],
        "phishing_pr_auc": uncal_metrics["phishing_focus"]["pr_auc"],
    }
    models_dict["uncalibrated"] = base_model

    # 2. Fit and evaluate each calibration method
    for method in candidate_methods:
        try:
            calibrator = fit_calibrator(base_model, val_ds.X, val_ds.y, method=method)
            cal_probs = calibrator.predict_proba(val_ds.X)
            cal_metrics = evaluate_predictions(val_ds.y, cal_probs, classes=TARGET_CLASSES)

            comparison[method] = {
                "brier_score": cal_metrics["brier_score"],
                "log_loss": cal_metrics["log_loss"],
                "expected_calibration_error": cal_metrics["expected_calibration_error"],
                "macro_f1": cal_metrics["macro_f1"],
                "phishing_f1": cal_metrics["phishing_focus"]["f1"],
                "phishing_pr_auc": cal_metrics["phishing_focus"]["pr_auc"],
            }
            models_dict[method] = calibrator
        except Exception as e:
            comparison[method] = {"error": str(e)}

    # 3. Decision Logic:
    # Priority 1: Lowest Brier score + Lowest ECE
    # Guard: Macro F1 must not degrade by > 0.005 compared to uncalibrated
    best_method = "uncalibrated"
    best_composite_score = float("inf")
    rationale = "Uncalibrated retained as baseline."

    for method, metrics in comparison.items():
        if "error" in metrics:
            continue
        # Check degradation guard
        f1_drop = uncal_metrics["macro_f1"] - metrics["macro_f1"]
        if f1_drop > 0.005:
            continue

        # Composite calibration error score: weighted combination of Brier and ECE
        # Both range [0, 1] for our task
        comp_score = metrics["brier_score"] + metrics["expected_calibration_error"]
        if comp_score < best_composite_score:
            best_composite_score = comp_score
            best_method = method
            rationale = (
                f"Selected {method} with Brier Score={metrics['brier_score']} "
                f"and ECE={metrics['expected_calibration_error']} "
                f"(Macro F1: {metrics['macro_f1']})."
            )

    return CalibrationComparisonResult(
        chosen_method=best_method,
        calibrated_model=models_dict[best_method],
        comparison_metrics=comparison,
        selection_rationale=rationale,
        model_version=FORENSIC_MODEL_VERSION,
    )
