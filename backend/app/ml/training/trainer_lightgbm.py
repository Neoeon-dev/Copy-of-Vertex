"""
Multiclass LightGBM Classifier Trainer for VERTEX Forensic Tabular ML.
Trains primary forensic tabular model with early stopping on validation split only,
evaluates natural vs balanced class weighting, and extracts gain & split feature importances.
"""
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import time
import os
import json
import warnings
import joblib
import numpy as np
import lightgbm as lgb
from lightgbm import LGBMClassifier, early_stopping, log_evaluation

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.evaluation.metrics import evaluate_predictions
from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES, INT_TO_LABEL


@dataclass
class LightGBMTrainingResult:
    """Result container for LightGBM model training."""
    model: LGBMClassifier
    train_metrics: Dict[str, Any]
    val_metrics: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    best_iteration: int
    feature_importances_gain: Dict[str, float]
    feature_importances_split: Dict[str, int]
    training_duration_seconds: float
    class_weight_strategy: Optional[str]
    model_version: str = FORENSIC_MODEL_VERSION

    def save(self, output_dir: str) -> None:
        """Serializes model booster, pickle, metrics, and feature importances."""
        os.makedirs(output_dir, exist_ok=True)

        # 1. Scikit-learn API model pickle
        joblib.dump(self.model, os.path.join(output_dir, "lightgbm_model.pkl"))

        # 2. Native LightGBM booster text representation
        if hasattr(self.model, "booster_") and self.model.booster_ is not None:
            self.model.booster_.save_model(os.path.join(output_dir, "lightgbm_booster.txt"))

        # 3. Metrics artifact
        metrics_payload = {
            "model_version": self.model_version,
            "model_type": "LightGBM",
            "class_weight_strategy": self.class_weight_strategy,
            "best_iteration": self.best_iteration,
            "training_duration_seconds": round(self.training_duration_seconds, 3),
            "hyperparameters": self.hyperparameters,
            "train_metrics": self.train_metrics,
            "val_metrics": self.val_metrics,
        }
        with open(os.path.join(output_dir, "lightgbm_metrics.json"), "w", encoding="utf-8") as f:
            json.dump(metrics_payload, f, indent=2)

        # 4. Feature importances artifact (gain and split)
        importances_payload = {
            "gain": self.feature_importances_gain,
            "split": self.feature_importances_split,
        }
        with open(os.path.join(output_dir, "feature_importances.json"), "w", encoding="utf-8") as f:
            json.dump(importances_payload, f, indent=2)


def extract_feature_importances(
    model: LGBMClassifier,
    feature_names: List[str],
) -> Tuple[Dict[str, float], Dict[str, int]]:
    """Extracts sorted gain and split feature importances."""
    if not hasattr(model, "booster_") or model.booster_ is None:
        return {}, {}

    gain_raw = model.booster_.feature_importance(importance_type="gain")
    split_raw = model.booster_.feature_importance(importance_type="split")

    gain_indices = np.argsort(gain_raw)[::-1]
    split_indices = np.argsort(split_raw)[::-1]

    gain_dict = {
        feature_names[i]: float(round(float(gain_raw[i]), 4))
        for i in gain_indices
    }
    split_dict = {
        feature_names[i]: int(split_raw[i])
        for i in split_indices
    }
    return gain_dict, split_dict


def train_lightgbm(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    learning_rate: float = 0.05,
    n_estimators: int = 600,
    num_leaves: int = 31,
    max_depth: int = -1,
    subsample: float = 0.8,
    colsample_bytree: float = 0.8,
    class_weight: Optional[str] = None,
    early_stopping_rounds: int = 30,
    random_state: int = 42,
    verbose: int = -1,
) -> LightGBMTrainingResult:
    """
    Trains multiclass LightGBM with early stopping evaluated on validation set.
    """
    start_time = time.time()

    hyperparams = {
        "objective": "multiclass",
        "num_class": len(TARGET_CLASSES),
        "learning_rate": learning_rate,
        "n_estimators": n_estimators,
        "num_leaves": num_leaves,
        "max_depth": max_depth,
        "subsample": subsample,
        "subsample_freq": 1 if subsample < 1.0 else 0,
        "colsample_bytree": colsample_bytree,
        "class_weight": class_weight,
        "random_state": random_state,
        "n_jobs": -1,
        "verbose": verbose,
    }

    model = LGBMClassifier(**hyperparams)

    # Suppress lightgbm deprecation warnings regarding eval_set
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        model.fit(
            train_ds.X,
            train_ds.y,
            eval_set=[(val_ds.X, val_ds.y)],
            callbacks=[
                early_stopping(stopping_rounds=early_stopping_rounds, verbose=False),
                log_evaluation(period=0),
            ],
        )

    duration = time.time() - start_time
    best_iter = getattr(model, "best_iteration_", n_estimators)

    # Predict probabilities
    train_probs = model.predict_proba(train_ds.X)
    val_probs = model.predict_proba(val_ds.X)

    # Evaluate metrics
    train_metrics = evaluate_predictions(train_ds.y, train_probs, classes=TARGET_CLASSES)
    val_metrics = evaluate_predictions(val_ds.y, val_probs, classes=TARGET_CLASSES)

    # Extract gain and split importances
    gain_dict, split_dict = extract_feature_importances(model, train_ds.feature_names)

    return LightGBMTrainingResult(
        model=model,
        train_metrics=train_metrics,
        val_metrics=val_metrics,
        hyperparameters=hyperparams,
        best_iteration=best_iter,
        feature_importances_gain=gain_dict,
        feature_importances_split=split_dict,
        training_duration_seconds=duration,
        class_weight_strategy=class_weight,
        model_version=FORENSIC_MODEL_VERSION,
    )


def compare_weighting_strategies(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    random_state: int = 42,
) -> Tuple[LightGBMTrainingResult, Dict[str, Any]]:
    """
    Trains both natural (None) and balanced class weighting strategies.
    Compares Macro F1 and Phishing PR-AUC on the validation split.
    Selects the champion configuration.
    """
    # 1. Natural weighting
    res_natural = train_lightgbm(
        train_ds,
        val_ds,
        class_weight=None,
        random_state=random_state,
    )

    # 2. Balanced weighting
    res_balanced = train_lightgbm(
        train_ds,
        val_ds,
        class_weight="balanced",
        random_state=random_state,
    )

    comparison_summary = {
        "natural": {
            "macro_f1": res_natural.val_metrics["macro_f1"],
            "phishing_pr_auc": res_natural.val_metrics["phishing_focus"]["pr_auc"],
            "phishing_f1": res_natural.val_metrics["phishing_focus"]["f1"],
            "brier_score": res_natural.val_metrics["brier_score"],
            "log_loss": res_natural.val_metrics["log_loss"],
            "best_iteration": res_natural.best_iteration,
        },
        "balanced": {
            "macro_f1": res_balanced.val_metrics["macro_f1"],
            "phishing_pr_auc": res_balanced.val_metrics["phishing_focus"]["pr_auc"],
            "phishing_f1": res_balanced.val_metrics["phishing_focus"]["f1"],
            "brier_score": res_balanced.val_metrics["brier_score"],
            "log_loss": res_balanced.val_metrics["log_loss"],
            "best_iteration": res_balanced.best_iteration,
        },
    }

    # Decision rule: Select higher Macro F1; if within 0.002, select higher Phishing PR-AUC
    natural_score = res_natural.val_metrics["macro_f1"]
    balanced_score = res_balanced.val_metrics["macro_f1"]

    if abs(natural_score - balanced_score) <= 0.002:
        natural_pr = res_natural.val_metrics["phishing_focus"]["pr_auc"]
        balanced_pr = res_balanced.val_metrics["phishing_focus"]["pr_auc"]
        winner = res_natural if natural_pr >= balanced_pr else res_balanced
        chosen_strategy = "natural" if natural_pr >= balanced_pr else "balanced"
    else:
        winner = res_natural if natural_score >= balanced_score else res_balanced
        chosen_strategy = "natural" if natural_score >= balanced_score else "balanced"

    comparison_summary["chosen_strategy"] = chosen_strategy
    return winner, comparison_summary
