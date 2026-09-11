"""
Production Inference Service for VERTEX Forensic Tabular ML.
Provides single-record, batch, and raw email threat prediction using calibrated tabular models.
Returns calibrated probabilities, risk scores, and explainable forensic feature attributions.
"""
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import os
import json
import time
import logging
import joblib
import numpy as np

from app.ml.version import FORENSIC_MODEL_VERSION, TARGET_CLASSES, INT_TO_LABEL
from app.features.registry import get_feature_names
from app.features.extractor import ForensicFeatureExtractor
from app.parsers.mime_parser import parse_email
from app.data.schema import CanonicalEmailRecord

logger = logging.getLogger(__name__)


@dataclass
class ForensicPrediction:
    """Structured inference output from VERTEX Forensic Tabular Model."""
    predicted_label: str  # 'legitimate' | 'spam' | 'phishing'
    confidence: float  # 0.0 to 1.0
    probabilities: Dict[str, float]  # class -> calibrated probability
    risk_score: float  # 0.0 to 1.0 composite risk
    top_contributing_features: List[Dict[str, Any]]
    model_version: str
    is_calibrated: bool
    features_used_count: int
    latency_ms: float
    calibration_method: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_label": self.predicted_label,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
            "risk_score": round(self.risk_score, 4),
            "top_contributing_features": self.top_contributing_features,
            "model_version": self.model_version,
            "is_calibrated": self.is_calibrated,
            "features_used_count": self.features_used_count,
            "latency_ms": round(self.latency_ms, 2),
            "calibration_method": self.calibration_method,
        }


class ForensicTabularService:
    """
    Production service hosting trained & calibrated forensic tabular models.
    Supports feature vector inputs, CanonicalEmailRecord, and raw MIME emails.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self.feature_names = get_feature_names()
        self.model: Optional[Any] = None
        self.is_calibrated: bool = False
        self.feature_importances: Dict[str, float] = {}
        self.metadata: Dict[str, Any] = {}
        self.extractor: Optional[ForensicFeatureExtractor] = None
        self.model_version = FORENSIC_MODEL_VERSION
        self.calibration_method = "unknown"
        self._load_model(model_dir)

    def _load_model(self, model_dir: Optional[str] = None) -> None:
        """Attempts to load calibrated or base model from prioritized paths."""
        candidate_dirs = []
        if model_dir is not None:
            candidate_dirs = [model_dir]
        else:
            candidate_dirs = [
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../models/forensic/v1")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../artifacts")),
                os.path.abspath("models/forensic/v1"),
                os.path.abspath("backend/app/ml/artifacts"),
            ]

        for path in candidate_dirs:
            if not os.path.isdir(path):
                continue

            calibrated_path = os.path.join(path, "calibrated_model.pkl")
            base_path = os.path.join(path, "lightgbm_model.pkl")
            importances_path = os.path.join(path, "feature_importances.json")
            meta_path = os.path.join(path, "metadata.json")

            try:
                if os.path.exists(calibrated_path):
                    self.model = joblib.load(calibrated_path)
                    self.is_calibrated = True
                    logger.info(f"Loaded forensic model from {calibrated_path}")
                elif os.path.exists(base_path):
                    self.model = joblib.load(base_path)
                    self.is_calibrated = False
                    logger.info(f"Loaded uncalibrated forensic model from {base_path}")

                if os.path.exists(importances_path):
                    with open(importances_path, "r", encoding="utf-8") as f:
                        imp_data = json.load(f)
                        self.feature_importances = imp_data.get("gain", {})

                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                        self.model_version = self.metadata.get("model_version", FORENSIC_MODEL_VERSION)
                        self.calibration_method = self.metadata.get("calibration_method", "unknown")
                        self.is_calibrated = self.calibration_method not in ("uncalibrated", "unknown", "none")

                if self.model is not None:
                    return
            except Exception as e:
                logger.warning(f"Failed loading model artifacts from {path}: {e}")

        logger.info("ForensicTabularService running in uninitialized/mock mode (no trained model loaded).")

    def predict_features(self, features: Dict[str, float]) -> ForensicPrediction:
        """Performs inference from a dictionary of forensic features."""
        start_time = time.perf_counter()

        # Build feature vector in canonical order
        row = np.array([
            float(features.get(name, -1.0)) for name in self.feature_names
        ], dtype=np.float32).reshape(1, -1)

        pred = self._predict_array(row, [features])[0]
        pred.latency_ms = (time.perf_counter() - start_time) * 1000.0
        return pred

    def predict_record(self, record: CanonicalEmailRecord) -> ForensicPrediction:
        """Performs feature extraction and inference from CanonicalEmailRecord."""
        start_time = time.perf_counter()
        if self.extractor is None:
            self.extractor = ForensicFeatureExtractor()

        if hasattr(self.extractor, "extract_from_record"):
            vec = self.extractor.extract_from_record(record)
        else:
            vec = self.extractor.extract_from_canonical_record(record)
        pred = self.predict_features(vec.features)
        pred.latency_ms = (time.perf_counter() - start_time) * 1000.0
        return pred

    def predict_raw_email(self, raw_bytes: bytes) -> ForensicPrediction:
        """Performs MIME parsing, forensic extraction, and threat classification."""
        start_time = time.perf_counter()
        if self.extractor is None:
            self.extractor = ForensicFeatureExtractor()

        parsed = parse_email(raw_bytes)
        vec = self.extractor.extract_from_raw_bytes(raw_bytes=raw_bytes)
        pred = self.predict_features(vec.features)
        pred.latency_ms = (time.perf_counter() - start_time) * 1000.0
        return pred

    def _predict_array(
        self,
        X: np.ndarray,
        feature_dicts: Optional[List[Dict[str, float]]] = None,
    ) -> List[ForensicPrediction]:
        """Internal batch inference on feature matrices."""
        n_samples = X.shape[0]

        if self.model is None:
            # Fallback heuristic if model is not yet trained/available
            predictions = []
            for i in range(n_samples):
                predictions.append(ForensicPrediction(
                    predicted_label="legitimate",
                    confidence=0.5,
                    probabilities={"legitimate": 0.5, "spam": 0.3, "phishing": 0.2},
                    risk_score=0.2,
                    top_contributing_features=[],
                    model_version=self.model_version,
                    is_calibrated=False,
                    features_used_count=len(self.feature_names),
                    latency_ms=0.0,
                    calibration_method=self.calibration_method,
                ))
            return predictions

        probs = self.model.predict_proba(X)
        predictions = []

        for i in range(n_samples):
            prob_vec = probs[i]
            pred_idx = int(np.argmax(prob_vec))
            pred_label = INT_TO_LABEL.get(pred_idx, "legitimate")
            conf = float(prob_vec[pred_idx])

            prob_dict = {
                TARGET_CLASSES[c]: float(round(float(prob_vec[c]), 4))
                for c in range(len(TARGET_CLASSES))
            }

            # Risk score: weighted threat score (Phishing * 1.0 + Spam * 0.45)
            risk = float(round(prob_dict.get("phishing", 0.0) * 1.0 + prob_dict.get("spam", 0.0) * 0.45, 4))
            risk = min(max(risk, 0.0), 1.0)

            # Top contributing features
            top_features = []
            f_dict = feature_dicts[i] if feature_dicts and i < len(feature_dicts) else {}
            if self.feature_importances and f_dict:
                # Top features sorted by importance where value is non-default/active
                candidates = []
                for fname, imp in self.feature_importances.items():
                    val = f_dict.get(fname, -1.0)
                    if val != -1.0 and val != 0.0:
                        candidates.append({
                            "feature": fname,
                            "value": val,
                            "importance_gain": imp,
                        })
                candidates.sort(key=lambda x: x["importance_gain"], reverse=True)
                top_features = candidates[:5]

            predictions.append(ForensicPrediction(
                predicted_label=pred_label,
                confidence=conf,
                probabilities=prob_dict,
                risk_score=risk,
                top_contributing_features=top_features,
                model_version=self.model_version,
                is_calibrated=self.is_calibrated,
                features_used_count=len(self.feature_names),
                latency_ms=0.0,
                calibration_method=self.calibration_method,
            ))

        return predictions


_FORENSIC_SERVICE_INSTANCE: Optional[ForensicTabularService] = None


def get_forensic_service(model_dir: Optional[str] = None) -> ForensicTabularService:
    """Retrieves or initializes the global singleton ForensicTabularService."""
    global _FORENSIC_SERVICE_INSTANCE
    if _FORENSIC_SERVICE_INSTANCE is None or model_dir is not None:
        _FORENSIC_SERVICE_INSTANCE = ForensicTabularService(model_dir=model_dir)
    return _FORENSIC_SERVICE_INSTANCE
