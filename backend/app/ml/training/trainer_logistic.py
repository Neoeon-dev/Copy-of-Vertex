"""
Multiclass Logistic Regression Baseline Trainer for VERTEX Forensic Tabular ML.
Standardizes tabular features, applies mean imputation, fits multinomial LogisticRegression,
and evaluates performance with comprehensive classification & calibration metrics.
"""
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import time
import os
import json
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.evaluation.metrics import evaluate_predictions
from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES, INT_TO_LABEL


@dataclass
class LogisticTrainingResult:
    """Result container for Logistic Regression baseline training."""
    pipeline: Pipeline
    train_metrics: Dict[str, Any]
    val_metrics: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    feature_coefficients: Dict[str, Dict[str, float]]
    training_duration_seconds: float
    model_version: str = FORENSIC_MODEL_VERSION

    def save(self, output_dir: str) -> None:
        """Serializes pipeline, metrics, hyperparameters, and coefficients."""
        os.makedirs(output_dir, exist_ok=True)
        # 1. Pipeline artifact
        model_path = os.path.join(output_dir, "logistic_baseline_pipeline.pkl")
        joblib.dump(self.pipeline, model_path)

        # 2. Metrics artifact
        metrics_payload = {
            "model_version": self.model_version,
            "model_type": "LogisticRegression",
            "hyperparameters": self.hyperparameters,
            "training_duration_seconds": round(self.training_duration_seconds, 3),
            "train_metrics": self.train_metrics,
            "val_metrics": self.val_metrics,
        }
        with open(os.path.join(output_dir, "logistic_baseline_metrics.json"), "w", encoding="utf-8") as f:
            json.dump(metrics_payload, f, indent=2)

        # 3. Top Coefficients artifact
        with open(os.path.join(output_dir, "logistic_coefficients.json"), "w", encoding="utf-8") as f:
            json.dump(self.feature_coefficients, f, indent=2)


def train_logistic_baseline(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    C: float = 1.0,
    max_iter: int = 1000,
    solver: str = "lbfgs",
    random_state: int = 42,
) -> LogisticTrainingResult:
    """
    Trains multinomial Logistic Regression on standardized tabular features.
    Pipeline fits ONLY on train_ds to prevent leakage.
    """
    start_time = time.time()

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="mean")),
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            C=C,
            max_iter=max_iter,
            solver=solver,
            random_state=random_state,
        )),
    ])

    pipeline.fit(train_ds.X, train_ds.y)
    duration = time.time() - start_time

    # Predict probabilities
    train_probs = pipeline.predict_proba(train_ds.X)
    val_probs = pipeline.predict_proba(val_ds.X)

    # Evaluate metrics
    train_metrics = evaluate_predictions(train_ds.y, train_probs, classes=TARGET_CLASSES)
    val_metrics = evaluate_predictions(val_ds.y, val_probs, classes=TARGET_CLASSES)

    # Extract feature coefficients
    clf: LogisticRegression = pipeline.named_steps["classifier"]
    feature_coefficients: Dict[str, Dict[str, float]] = {}
    
    # clf.coef_ shape: (n_classes, n_features)
    for class_idx, class_name in enumerate(TARGET_CLASSES):
        coefs = clf.coef_[class_idx]
        sorted_indices = np.argsort(np.abs(coefs))[::-1]
        feature_coefficients[class_name] = {
            train_ds.feature_names[idx]: float(round(float(coefs[idx]), 5))
            for idx in sorted_indices[:20]  # top 20 influential features
        }

    hyperparams = {
        "C": C,
        "max_iter": max_iter,
        "solver": solver,
        "random_state": random_state,
        "imputer_strategy": "mean",
        "scaler": "StandardScaler",
    }

    return LogisticTrainingResult(
        pipeline=pipeline,
        train_metrics=train_metrics,
        val_metrics=val_metrics,
        hyperparameters=hyperparams,
        feature_coefficients=feature_coefficients,
        training_duration_seconds=duration,
        model_version=FORENSIC_MODEL_VERSION,
    )
