"""
Data schemas and type definitions for VERTEX Multimodal Evidence-Aware Fusion (Phase D4).
Defines contracts for evidence quality, fusion predictions, disagreement types, and strategies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class QualityTier(str, Enum):
    """Categorical tiers for email forensic evidence quality."""
    HIGH = "HIGH"          # >= 0.70: Rich headers, auth, relay, and body available
    MEDIUM = "MEDIUM"      # 0.40 <= Q < 0.70: Moderate evidence, partial headers/auth
    LOW = "LOW"            # 0.20 <= Q < 0.40: Sparse evidence, missing headers or auth
    DEGRADED = "DEGRADED"  # < 0.20: Body-only or heavily stripped, missing almost all metadata


class DisagreementCategory(str, Enum):
    """Categorization of predictions between Forensic (D2) and Semantic (D3) models."""
    AGREEMENT = "AGREEMENT"
    FORENSIC_PHISH_SEMANTIC_LEGIT = "FORENSIC_PHISH_SEMANTIC_LEGIT"
    FORENSIC_LEGIT_SEMANTIC_PHISH = "FORENSIC_LEGIT_SEMANTIC_PHISH"
    FORENSIC_SPAM_SEMANTIC_PHISH = "FORENSIC_SPAM_SEMANTIC_PHISH"
    FORENSIC_PHISH_SEMANTIC_SPAM = "FORENSIC_PHISH_SEMANTIC_SPAM"
    FORENSIC_LEGIT_SEMANTIC_SPAM = "FORENSIC_LEGIT_SEMANTIC_SPAM"
    FORENSIC_SPAM_SEMANTIC_LEGIT = "FORENSIC_SPAM_SEMANTIC_LEGIT"

    @classmethod
    def categorize(cls, d2_label: str, d3_label: str) -> DisagreementCategory:
        """Determines the disagreement category from two predicted labels."""
        if d2_label.lower() == d3_label.lower():
            return cls.AGREEMENT
        norm = {
            "legitimate": "LEGIT",
            "legit": "LEGIT",
            "spam": "SPAM",
            "phishing": "PHISH",
            "phish": "PHISH",
        }
        d2_k = norm.get(d2_label.lower(), d2_label.upper())
        d3_k = norm.get(d3_label.lower(), d3_label.upper())
        key = f"FORENSIC_{d2_k}_SEMANTIC_{d3_k}"
        try:
            return cls[key]
        except KeyError:
            return cls.AGREEMENT


class FusionStrategy(str, Enum):
    """Supported multimodal fusion strategies."""
    FORENSIC_ONLY = "forensic_only"
    SEMANTIC_ONLY = "semantic_only"
    EQUAL_AVERAGE = "equal_average"
    FIXED_WEIGHTED = "fixed_weighted"
    SMOOTH_EVIDENCE_WEIGHTED = "smooth_evidence_weighted"
    LEARNED_LOGISTIC = "learned_logistic"


@dataclass
class EvidenceDimensionScore:
    """Quantitative score for one observable evidence dimension."""
    dimension_name: str
    score: float  # 0.0 to 1.0
    weight: float
    active_signals: int
    total_signals: int
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension_name": self.dimension_name,
            "score": round(self.score, 4),
            "weight": round(self.weight, 4),
            "active_signals": self.active_signals,
            "total_signals": self.total_signals,
            "description": self.description,
        }


@dataclass
class EvidenceQuality:
    """Comprehensive evidence quality evaluation across 10 observable dimensions."""
    overall_quality: float  # Continuous 0.0 to 1.0
    tier: str               # HIGH, MEDIUM, LOW, DEGRADED
    dimension_scores: Dict[str, float]
    dimension_details: List[EvidenceDimensionScore]
    missing_evidence_flags: List[str]
    active_features_count: int
    total_features_count: int = 125

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_quality": round(self.overall_quality, 4),
            "tier": self.tier,
            "dimension_scores": {k: round(v, 4) for k, v in self.dimension_scores.items()},
            "dimension_details": [d.to_dict() for d in self.dimension_details],
            "missing_evidence_flags": self.missing_evidence_flags,
            "active_features_count": self.active_features_count,
            "total_features_count": self.total_features_count,
        }


@dataclass
class FusionPrediction:
    """Unified prediction output from VERTEX Multimodal Evidence-Aware Fusion."""
    predicted_label: str          # 'legitimate' | 'spam' | 'phishing'
    predicted_index: int          # 0, 1, 2
    confidence: float             # max probability [0.0, 1.0]
    probabilities: Dict[str, float]  # class -> calibrated probability
    risk_score: float             # composite threat risk score [0.0, 1.0]
    fusion_strategy: str          # e.g. 'smooth_evidence_weighted'
    alpha: float                  # forensic weight (semantic weight = 1 - alpha)
    evidence_quality: EvidenceQuality
    disagreement_category: str    # DisagreementCategory string
    uncertainty_escalation: bool  # whether manual review or escalation is flagged
    escalation_reasons: List[str]
    reasoning: List[str]          # human-readable explainability bullet points
    forensic_prediction: Optional[Dict[str, Any]] = None
    semantic_prediction: Optional[Dict[str, Any]] = None
    model_version: str = "1.0.0"
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_label": self.predicted_label,
            "predicted_index": self.predicted_index,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
            "risk_score": round(self.risk_score, 4),
            "fusion_strategy": self.fusion_strategy,
            "alpha": round(self.alpha, 4),
            "evidence_quality": self.evidence_quality.to_dict(),
            "disagreement_category": self.disagreement_category,
            "uncertainty_escalation": self.uncertainty_escalation,
            "escalation_reasons": self.escalation_reasons,
            "reasoning": self.reasoning,
            "forensic_prediction": self.forensic_prediction,
            "semantic_prediction": self.semantic_prediction,
            "model_version": self.model_version,
            "latency_ms": round(self.latency_ms, 2),
        }
