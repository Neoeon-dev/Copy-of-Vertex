"""
Canonical Forensic Risk Engine Package for VERTEX (Phase D5).
Exports the canonical decision engine, schemas, registry, and factor definitions.
"""
from app.engine.schemas import (
    RiskLevel,
    score_to_severity,
    EvidenceState,
    RiskFactorCategory,
    EvidenceProvenance,
    RiskFactor,
    EvidenceQualityBreakdown,
    ModelEvidence,
    RiskAssessment,
)
from app.engine.registry import (
    RiskFactorRegistry,
    CATEGORY_CAPS,
    FactorDefinition,
    get_default_registry,
)
from app.engine.risk_engine import (
    CanonicalRiskEngine,
    get_canonical_risk_engine,
    calculate_tvd,
    shannon_entropy,
    ENGINE_VERSION,
    FEATURE_VERSION,
    RULE_SET_VERSION,
)

__all__ = [
    "RiskLevel",
    "score_to_severity",
    "EvidenceState",
    "RiskFactorCategory",
    "EvidenceProvenance",
    "RiskFactor",
    "EvidenceQualityBreakdown",
    "ModelEvidence",
    "RiskAssessment",
    "RiskFactorRegistry",
    "CATEGORY_CAPS",
    "FactorDefinition",
    "get_default_registry",
    "CanonicalRiskEngine",
    "get_canonical_risk_engine",
    "calculate_tvd",
    "shannon_entropy",
    "ENGINE_VERSION",
    "FEATURE_VERSION",
    "RULE_SET_VERSION",
]
