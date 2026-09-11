"""
Probability calibration for Phase D3 Semantic Transformer.
Implements Temperature Scaling and metric calculation (ECE, Brier score, Reliability curve).
"""
from __future__ import annotations

import json
import os
from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
from scipy.optimize import minimize


def compute_ece(
    probs: np.ndarray,
    labels: np.ndarray,
    n_bins: int = 10,
) -> float:
    """
    Computes Expected Calibration Error (ECE) for multiclass predictions.
    """
    confidences = np.max(probs, axis=1)
    predictions = np.argmax(probs, axis=1)
    accuracies = (predictions == labels).astype(float)

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    total_samples = len(labels)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = np.mean(in_bin)

        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

    return float(ece)


class TemperatureScalingCalibrator:
    """
    Learns a scalar temperature T on validation logits to minimize Negative Log Likelihood.
    Preserves logit argmax while producing calibrated probabilities.
    """

    def __init__(self, temperature: float = 1.0) -> None:
        self.temperature = float(temperature)
        self.is_fitted = False

    def fit(self, val_logits: np.ndarray, val_labels: np.ndarray) -> TemperatureScalingCalibrator:
        """
        Optimizes temperature T using L-BFGS on validation logits and labels.
        """
        logits_t = torch.tensor(val_logits, dtype=torch.float32)
        labels_t = torch.tensor(val_labels, dtype=torch.long)
        criterion = nn.CrossEntropyLoss()

        def eval_nll(t_val: Any) -> float:
            t = float(max(float(np.squeeze(t_val)), 1e-3))
            scaled = logits_t / t
            loss = criterion(scaled, labels_t).item()
            return loss

        res = minimize(
            eval_nll,
            x0=[1.0],
            bounds=[(0.05, 10.0)],
            method="L-BFGS-B",
        )

        self.temperature = float(res.x[0])
        self.is_fitted = True
        return self

    def calibrate_logits(self, logits: np.ndarray) -> np.ndarray:
        """Scales logits by temperature."""
        return logits / self.temperature

    def predict_proba(self, logits: np.ndarray) -> np.ndarray:
        """Calculates calibrated probabilities via temperature-scaled softmax."""
        scaled = logits / self.temperature
        # Numerically stable softmax
        exp_scaled = np.exp(scaled - np.max(scaled, axis=1, keepdims=True))
        return exp_scaled / np.sum(exp_scaled, axis=1, keepdims=True)

    def evaluate_calibration(
        self,
        uncalibrated_probs: np.ndarray,
        calibrated_probs: np.ndarray,
        labels: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Compares ECE, Brier score, and Log Loss before and after calibration.
        """
        num_classes = uncalibrated_probs.shape[1]
        one_hot = np.zeros((len(labels), num_classes))
        for i, c in enumerate(labels):
            if 0 <= c < num_classes:
                one_hot[i, c] = 1.0

        uncal_brier = float(np.mean(np.sum((uncalibrated_probs - one_hot) ** 2, axis=1)))
        cal_brier = float(np.mean(np.sum((calibrated_probs - one_hot) ** 2, axis=1)))

        uncal_ece = compute_ece(uncalibrated_probs, labels)
        cal_ece = compute_ece(calibrated_probs, labels)

        # Small epsilon for log loss stability
        eps = 1e-12
        uncal_ll = -float(np.mean(np.sum(one_hot * np.log(np.clip(uncalibrated_probs, eps, 1.0)), axis=1)))
        cal_ll = -float(np.mean(np.sum(one_hot * np.log(np.clip(calibrated_probs, eps, 1.0)), axis=1)))

        return {
            "temperature": round(self.temperature, 4),
            "uncalibrated": {
                "ece": round(uncal_ece, 4),
                "brier_score": round(uncal_brier, 4),
                "log_loss": round(uncal_ll, 4),
            },
            "calibrated": {
                "ece": round(cal_ece, 4),
                "brier_score": round(cal_brier, 4),
                "log_loss": round(cal_ll, 4),
            },
            "ece_reduction": round(uncal_ece - cal_ece, 4),
            "brier_reduction": round(uncal_brier - cal_brier, 4),
        }

    def save(self, filepath: str) -> None:
        """Saves calibration config to JSON."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump({"temperature": self.temperature, "is_fitted": self.is_fitted}, f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> TemperatureScalingCalibrator:
        """Loads calibration config from JSON."""
        with open(filepath) as f:
            data = json.load(f)
        cal = cls(temperature=data.get("temperature", 1.0))
        cal.is_fitted = data.get("is_fitted", False)
        return cal
