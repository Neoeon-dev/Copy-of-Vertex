"""
VERTEX Phase D4: Multimodal Evidence-Aware Fusion Package.
Combines Forensic Tabular ML (D2) and Semantic NLP Transformer (D3)
with observable evidence quality analysis and adaptive routing.
"""
from app.ml.fusion.schemas import (
    QualityTier,
    DisagreementCategory,
    FusionStrategy,
    EvidenceDimensionScore,
    EvidenceQuality,
    FusionPrediction,
)
from app.ml.fusion.evidence_quality import (
    EvidenceQualityAnalyzer,
    DIMENSION_WEIGHTS,
)
from app.ml.fusion.fusion import (
    SmoothEvidenceRouter,
    EvidenceAwareFusionEngine,
)
from app.ml.fusion.calibrator import (
    FusionCalibrator,
)
from app.ml.fusion.service import (
    MultimodalFusionService,
    get_fusion_service,
    FUSION_MODEL_VERSION,
)

__all__ = [
    "QualityTier",
    "DisagreementCategory",
    "FusionStrategy",
    "EvidenceDimensionScore",
    "EvidenceQuality",
    "FusionPrediction",
    "EvidenceQualityAnalyzer",
    "DIMENSION_WEIGHTS",
    "SmoothEvidenceRouter",
    "EvidenceAwareFusionEngine",
    "FusionCalibrator",
    "MultimodalFusionService",
    "get_fusion_service",
    "FUSION_MODEL_VERSION",
]
