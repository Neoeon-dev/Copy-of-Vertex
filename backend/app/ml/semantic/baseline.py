"""
Classical text classification baseline (TF-IDF + Logistic Regression) for Phase D3.
Provides the classical text reference point against which the semantic transformer is evaluated.
"""
from __future__ import annotations

import os
import joblib
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    brier_score_loss,
    log_loss,
    precision_recall_curve,
    auc,
    roc_auc_score,
    confusion_matrix,
)

from app.ml.version import LABEL_TO_INT, INT_TO_LABEL, TARGET_CLASSES


class TfidfLogisticBaseline:
    """
    Classical NLP baseline combining n-gram TF-IDF representations with balanced Logistic Regression.
    """

    def __init__(
        self,
        max_features: int = 10000,
        ngram_range: Tuple[int, int] = (1, 2),
        sublinear_tf: bool = True,
        C: float = 1.0,
        class_weight: str = "balanced",
        random_state: int = 42,
    ) -> None:
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.sublinear_tf = sublinear_tf
        self.C = C
        self.class_weight = class_weight
        self.random_state = random_state

        self.vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=self.ngram_range,
            sublinear_tf=self.sublinear_tf,
            token_pattern=r"(?u)\b\w+\b|\[\w+\]",  # Capture special tokens like [URL], [MONEY]
        )
        self.classifier = LogisticRegression(
            C=self.C,
            class_weight=self.class_weight,
            max_iter=1000,
            random_state=self.random_state,
            solver="lbfgs",
        )
        self.is_fitted = False

    def fit(self, texts: List[str], labels: np.ndarray) -> TfidfLogisticBaseline:
        """Fits TF-IDF vectorizer and trains Logistic Regression."""
        X = self.vectorizer.fit_transform(texts)
        self.classifier.fit(X, labels)
        self.is_fitted = True
        return self

    def predict_proba(self, texts: List[str]) -> np.ndarray:
        """Predicts class probabilities."""
        if not self.is_fitted:
            raise RuntimeError("Baseline model is not fitted.")
        X = self.vectorizer.transform(texts)
        return self.classifier.predict_proba(X)

    def predict(self, texts: List[str]) -> np.ndarray:
        """Predicts class labels."""
        if not self.is_fitted:
            raise RuntimeError("Baseline model is not fitted.")
        X = self.vectorizer.transform(texts)
        return self.classifier.predict(X)

    def evaluate(self, texts: List[str], y_true: np.ndarray) -> Dict[str, Any]:
        """Calculates comprehensive evaluation metrics."""
        y_prob = self.predict_proba(texts)
        y_pred = np.argmax(y_prob, axis=1)

        acc = float(accuracy_score(y_true, y_pred))
        prec, rec, f1, supp = precision_recall_fscore_support(
            y_true, y_pred, labels=[0, 1, 2], average=None, zero_division=0
        )
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="weighted", zero_division=0
        )

        # Phishing-specific binary evaluation (class index 2)
        phish_mask = (y_true == 2).astype(int)
        phish_probs = y_prob[:, 2] if y_prob.shape[1] > 2 else y_prob[:, -1]
        
        # Check if phishing samples exist in y_true
        if np.sum(phish_mask) > 0 and np.sum(phish_mask) < len(phish_mask):
            p_prec, p_rec, _ = precision_recall_curve(phish_mask, phish_probs)
            phish_pr_auc = float(auc(p_rec, p_prec))
            phish_roc_auc = float(roc_auc_score(phish_mask, phish_probs))
        else:
            phish_pr_auc = float(np.nan)
            phish_roc_auc = float(np.nan)

        # Multiclass Brier and Log loss (when all classes represented)
        present_classes = np.unique(y_true)
        if len(present_classes) == 3:
            y_true_onehot = np.zeros((len(y_true), 3))
            for i, c in enumerate(y_true):
                y_true_onehot[i, c] = 1.0
            brier = float(np.mean(np.sum((y_prob - y_true_onehot) ** 2, axis=1)))
            ll = float(log_loss(y_true, y_prob, labels=[0, 1, 2]))
        else:
            brier = float(np.nan)
            ll = float(np.nan)

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist()

        return {
            "accuracy": round(acc, 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "per_class": {
                "legitimate": {
                    "precision": round(float(prec[0]), 4),
                    "recall": round(float(rec[0]), 4),
                    "f1": round(float(f1[0]), 4),
                    "support": int(supp[0]),
                },
                "spam": {
                    "precision": round(float(prec[1]), 4),
                    "recall": round(float(rec[1]), 4),
                    "f1": round(float(f1[1]), 4),
                    "support": int(supp[1]),
                },
                "phishing": {
                    "precision": round(float(prec[2]), 4),
                    "recall": round(float(rec[2]), 4),
                    "f1": round(float(f1[2]), 4),
                    "support": int(supp[2]),
                },
            },
            "phishing_metrics": {
                "precision": round(float(prec[2]), 4),
                "recall": round(float(rec[2]), 4),
                "f1": round(float(f1[2]), 4),
                "pr_auc": round(phish_pr_auc, 4) if not np.isnan(phish_pr_auc) else None,
                "roc_auc": round(phish_roc_auc, 4) if not np.isnan(phish_roc_auc) else None,
            },
            "brier_score": round(brier, 4) if not np.isnan(brier) else None,
            "log_loss": round(ll, 4) if not np.isnan(ll) else None,
            "confusion_matrix": cm,
        }

    def save(self, filepath: str) -> None:
        """Saves fitted baseline to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> TfidfLogisticBaseline:
        """Loads baseline from disk."""
        return joblib.load(filepath)
