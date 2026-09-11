"""ML Schemas and Data Transfer Objects for VERTEX.

Defines standardized data structures for model inputs, feature vectors,
classification results, explainability payloads, and model metadata.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


@dataclass
class ClassificationResult:
    """Result of email classification with explainable signals.

    Preserves full backwards-compatibility with the prototype classifier
    while providing foundation for multi-tier ensemble results.
    """

    label: str  # legitimate | suspicious | phishing | spam
    confidence: float  # 0.0 – 1.0
    probabilities: dict[str, float] = field(default_factory=dict)
    signals: dict[str, float] = field(default_factory=dict)  # signal_name → 0.0–1.0
    signal_details: dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.0  # 0.0 – 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "probabilities": {k: round(v, 3) for k, v in self.probabilities.items()},
            "signals": {k: round(v, 3) for k, v in self.signals.items()},
            "signal_details": self.signal_details,
            "risk_score": round(self.risk_score, 3),
        }


class ModelMetadata(BaseModel):
    """Metadata manifest schema for serialized production models."""

    model_name: str
    model_version: str
    architecture: str  # e.g. "LightGBM-Tabular", "DeBERTa-v3-small"
    trained_at: str
    git_commit: Optional[str] = None
    sha256_checksum: str
    metrics: Dict[str, float] = Field(default_factory=dict)  # roc_auc, f1, precision, recall
    feature_names: List[str] = Field(default_factory=list)
    calibration_method: Optional[str] = None  # "platt", "isotonic"


class FeatureContribution(BaseModel):
    """SHAP or heuristic feature contribution for explainable AI."""

    feature_name: str
    display_name: str
    value: Any
    contribution_score: float  # Positive = adds risk, Negative = reduces risk
    description: str


class MLInferencePayload(BaseModel):
    """Standardized API payload for multi-tier ML inferences."""

    email_id: Optional[int] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_name: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
