"""
Calibration and reliability metrics for VERTEX Multimodal Fusion (Phase D4).
Calculates Expected Calibration Error (ECE), Maximum Calibration Error (MCE),
Multiclass Brier score, and bin diagnostics for reliability diagrams.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
import numpy as np


class FusionCalibrator:
    """
    Evaluates probability calibration and reliability across multiclass threat predictions.
    """

    @staticmethod
    def calculate_multiclass_brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
        """
        Calculates the standard multi-class Brier score:
        Brier = (1/N) * sum_i sum_c (p_ic - y_ic)^2
        Range: 0.0 (perfect) to 2.0 (worst).
        """
        n_samples, n_classes = y_prob.shape
        # One-hot encode targets
        y_one_hot = np.zeros((n_samples, n_classes), dtype=np.float64)
        for i, target in enumerate(y_true):
            if 0 <= target < n_classes:
                y_one_hot[i, target] = 1.0

        brier = np.mean(np.sum((y_prob - y_one_hot) ** 2, axis=1))
        return float(round(float(brier), 6))

    @staticmethod
    def calculate_ece_and_bins(
        y_true: np.ndarray,
        y_prob: np.ndarray,
        n_bins: int = 10,
    ) -> Tuple[float, float, List[Dict[str, Any]]]:
        """
        Calculates Expected Calibration Error (ECE) and Maximum Calibration Error (MCE),
        along with bin statistics for reliability diagrams.
        """
        confidences = np.max(y_prob, axis=1)
        predictions = np.argmax(y_prob, axis=1)
        accuracies = (predictions == y_true).astype(np.float64)

        bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        mce = 0.0
        bin_data: List[Dict[str, Any]] = []

        n_samples = len(y_true)

        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]

            if i == n_bins - 1:
                in_bin = (confidences >= bin_lower) & (confidences <= bin_upper)
            else:
                in_bin = (confidences >= bin_lower) & (confidences < bin_upper)

            bin_count = int(np.sum(in_bin))
            if bin_count > 0:
                bin_acc = float(np.mean(accuracies[in_bin]))
                bin_conf = float(np.mean(confidences[in_bin]))
                bin_err = abs(bin_acc - bin_conf)

                ece += (bin_count / n_samples) * bin_err
                mce = max(mce, bin_err)

                bin_data.append({
                    "bin_index": i,
                    "bin_lower": round(float(bin_lower), 3),
                    "bin_upper": round(float(bin_upper), 3),
                    "sample_count": bin_count,
                    "accuracy": round(bin_acc, 4),
                    "confidence": round(bin_conf, 4),
                    "calibration_error": round(bin_err, 4),
                })
            else:
                bin_data.append({
                    "bin_index": i,
                    "bin_lower": round(float(bin_lower), 3),
                    "bin_upper": round(float(bin_upper), 3),
                    "sample_count": 0,
                    "accuracy": 0.0,
                    "confidence": 0.0,
                    "calibration_error": 0.0,
                })

        return float(round(ece, 6)), float(round(mce, 6)), bin_data
