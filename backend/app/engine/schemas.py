"""
Canonical Risk Assessment Schemas and Contracts for VERTEX (Phase D5).
Defines standard contracts separating Threat Probability, Forensic Risk,
Confidence, Uncertainty, Evidence Quality, and Severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class RiskLevel(str, Enum):
    """Canonical 4-tier forensic risk severity."""
    LOW = "LOW"            # 0.0 - 24.99
    MEDIUM = "MEDIUM"      # 25.0 - 49.99
    HIGH = "HIGH"          # 50.0 - 74.99
    CRITICAL = "CRITICAL"  # 75.0 - 100.0


def score_to_severity(score: float) -> RiskLevel:
    """Converts a bounded 0-100 forensic risk score into canonical severity."""
    s = min(100.0, max(0.0, float(score)))
    if s >= 75.0:
        return RiskLevel.CRITICAL
    elif s >= 50.0:
        return RiskLevel.HIGH
    elif s >= 25.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class EvidenceState(str, Enum):
    """Explicit observation state for forensic signals (Missing != Failed)."""
    OBSERVED_POSITIVE = "OBSERVED_POSITIVE"  # Verified clean / passing check
    OBSERVED_NEGATIVE = "OBSERVED_NEGATIVE"  # Verified anomaly / failing check
    UNAVAILABLE = "UNAVAILABLE"              # Evidence missing / stripped from email
    NOT_APPLICABLE = "NOT_APPLICABLE"        # Factor not applicable (e.g. 0 attachments)
    ANALYSIS_FAILED = "ANALYSIS_FAILED"      # Extraction / parser crashed or timed out
    UNCERTAIN = "UNCERTAIN"                  # Ambiguous or contradictory observation


class RiskFactorCategory(str, Enum):
    """Functional categories for forensic risk factors."""
    MODEL = "MODEL"
    AUTHENTICATION = "AUTHENTICATION"
    IDENTITY = "IDENTITY"
    DOMAIN = "DOMAIN"
    URL = "URL"
    ATTACHMENT = "ATTACHMENT"
    INFRASTRUCTURE_RELAY = "INFRASTRUCTURE_RELAY"
    CONTENT_BEC = "CONTENT_BEC"
    EVIDENCE = "EVIDENCE"


@dataclass
class EvidenceProvenance:
    """Traceable provenance and extraction origin for a forensic risk factor."""
    source_analyzer: str
    source_feature: str
    raw_value: Any
    normalized_value: float
    evidence_state: str = EvidenceState.OBSERVED_NEGATIVE.value
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_analyzer": self.source_analyzer,
            "source_feature": self.source_feature,
            "raw_value": str(self.raw_value) if self.raw_value is not None else None,
            "normalized_value": round(float(self.normalized_value), 4),
            "evidence_state": self.evidence_state,
            "description": self.description,
        }


@dataclass
class RiskFactor:
    """Standardized forensic risk factor with stable ID, contribution, and provenance."""
    factor_id: str                      # e.g. "AUTH_DMARC_FAIL"
    category: str                       # e.g. "AUTHENTICATION"
    name: str                           # Human-readable title
    description: str                    # Detailed technical observation
    contribution: float                 # Point contribution to category score (-100 to +100)
    max_contribution: float             # Maximum potential points
    direction: str = "INCREASE_RISK"    # "INCREASE_RISK" | "REDUCE_RISK"
    evidence_state: str = EvidenceState.OBSERVED_NEGATIVE.value
    provenance: Optional[EvidenceProvenance] = None
    explanation: str = ""
    version: str = "5.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "factor_id": self.factor_id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "contribution": round(self.contribution, 2),
            "max_contribution": round(self.max_contribution, 2),
            "direction": self.direction,
            "evidence_state": self.evidence_state,
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "explanation": self.explanation,
            "version": self.version,
        }


@dataclass
class EvidenceQualityBreakdown:
    """Multi-aspect decomposition of evidence quality for decision confidence."""
    availability: float                 # Ratio of observed vs possible forensic fields (0.0 - 1.0)
    reliability: float                  # Cryptographic/source tamper-resistance (0.0 - 1.0)
    consistency: float                  # Cross-modality and signal concordance (0.0 - 1.0)
    overall: float                      # Composite evidence quality Q (0.0 - 1.0)
    tier: str                           # HIGH, MEDIUM, LOW, DEGRADED
    missing_evidence_flags: List[str]   # Flags for missing critical categories
    dimension_scores: Dict[str, float] = field(default_factory=dict)
    body_chars: int = 0

    @property
    def overall_score(self) -> float:
        return self.overall

    def to_dict(self) -> Dict[str, Any]:
        return {
            "availability": round(self.availability, 4),
            "reliability": round(self.reliability, 4),
            "consistency": round(self.consistency, 4),
            "overall": round(self.overall, 4),
            "overall_score": round(self.overall, 4),
            "tier": self.tier,
            "missing_evidence_flags": self.missing_evidence_flags,
            "dimension_scores": {k: round(v, 4) for k, v in self.dimension_scores.items()},
            "body_chars": self.body_chars,
        }


@dataclass
class ModelEvidence:
    """Detailed ML threat evidence consumed by the risk engine."""
    d2_probability: Dict[str, float]
    d3_probability: Dict[str, float]
    fused_probability: Dict[str, float]
    disagreement: float                 # Total Variation Distance in [0.0, 1.0]
    disagreement_category: str          # Categorical disagreement enum
    selected_strategy: str              # e.g. "smooth_evidence_weighted"
    model_confidence: float             # Max probability of fused model
    d2_available: bool = True
    d3_available: bool = True

    @property
    def disagreement_tvd(self) -> float:
        return self.disagreement

    def to_dict(self) -> Dict[str, Any]:
        return {
            "d2_probability": {k: round(v, 4) for k, v in self.d2_probability.items()},
            "d3_probability": {k: round(v, 4) for k, v in self.d3_probability.items()},
            "fused_probability": {k: round(v, 4) for k, v in self.fused_probability.items()},
            "disagreement": round(self.disagreement, 4),
            "disagreement_tvd": round(self.disagreement, 4),
            "disagreement_category": self.disagreement_category,
            "selected_strategy": self.selected_strategy,
            "model_confidence": round(self.model_confidence, 4),
            "d2_available": self.d2_available,
            "d3_available": self.d3_available,
        }


@dataclass
class RiskAssessment:
    """
    Canonical forensic risk assessment for VERTEX.
    Unifies ML probability, forensic indicators, evidence quality, and uncertainty.
    """
    risk_score: float                               # Bounded 0.0 - 100.0
    severity: str                                   # LOW, MEDIUM, HIGH, CRITICAL
    threat_probabilities: Dict[str, float]          # legitimate, spam, phishing (sums to 1.0)
    predicted_threat_label: str                     # 'legitimate' | 'spam' | 'phishing'
    confidence: float                               # Decision confidence [0.0, 1.0]
    uncertainty: float                              # Decision uncertainty [0.0, 1.0]
    evidence_quality: EvidenceQualityBreakdown
    model_evidence: ModelEvidence
    category_scores: Dict[str, float]               # Per-category score (capped)
    category_caps: Dict[str, float]                 # Category point limits
    risk_factors: List[RiskFactor]                  # Active contributing risk factors
    explanation: str                                # Deterministic human-readable explanation
    limitations: List[str]                          # Contextual caveats and boundaries
    engine_version: str = "5.0.0"
    feature_version: str = "1.0.0"
    rule_set_version: str = "2026.1"

    # Backward compatibility properties
    @property
    def score(self) -> float:
        return self.risk_score

    @property
    def level(self) -> str:
        return self.severity

    @property
    def summary(self) -> str:
        return self.explanation

    @property
    def contributions(self) -> List[Any]:
        """Provides backward compatibility with legacy SignalContribution objects."""
        legacy_list = []
        from app.forensics.risk_engine import SignalContribution
        for rf in self.risk_factors:
            raw_v = rf.provenance.normalized_value if rf.provenance else min(1.0, max(0.0, rf.contribution / max(rf.max_contribution, 1.0)))
            legacy_list.append(
                SignalContribution(
                    category=rf.category.lower(),
                    signal=rf.factor_id.lower(),
                    raw_value=raw_v,
                    weight=rf.max_contribution / 100.0,
                    contribution=rf.contribution,
                    description=rf.explanation or rf.description,
                    confidence="observed" if rf.evidence_state == EvidenceState.OBSERVED_NEGATIVE.value else "inference",
                )
            )
        return legacy_list

    def to_dict(self) -> Dict[str, Any]:
        """Produces full serialized assessment with both canonical and backward-compatible fields."""
        legacy_contribs = []
        for rf in self.risk_factors:
            raw_v = rf.provenance.normalized_value if rf.provenance else min(1.0, max(0.0, rf.contribution / max(rf.max_contribution, 1.0)))
            legacy_contribs.append({
                "category": rf.category.lower(),
                "signal": rf.factor_id.lower(),
                "raw_value": round(float(raw_v), 3),
                "weight": round(float(rf.max_contribution / 100.0), 3),
                "contribution": round(float(rf.contribution), 3),
                "description": rf.explanation or rf.description,
                "confidence": "observed" if rf.evidence_state == EvidenceState.OBSERVED_NEGATIVE.value else "inference",
            })

        return {
            # Canonical D5 fields
            "risk_score": round(self.risk_score, 1),
            "severity": self.severity,
            "threat_probabilities": {k: round(v, 4) for k, v in self.threat_probabilities.items()},
            "predicted_threat_label": self.predicted_threat_label,
            "confidence": round(self.confidence, 4),
            "uncertainty": round(self.uncertainty, 4),
            "evidence_quality": self.evidence_quality.to_dict(),
            "model_evidence": self.model_evidence.to_dict(),
            "category_scores": {k: round(v, 1) for k, v in self.category_scores.items()},
            "category_caps": {k: round(v, 1) for k, v in self.category_caps.items()},
            "risk_factors": [rf.to_dict() for rf in self.risk_factors],
            "explanation": self.explanation,
            "limitations": self.limitations,
            "engine_version": self.engine_version,
            "feature_version": self.feature_version,
            "rule_set_version": self.rule_set_version,
            # Legacy compatibility aliases
            "score": round(self.risk_score, 1),
            "level": self.severity,
            "summary": self.explanation,
            "contributions": legacy_contribs,
        }
