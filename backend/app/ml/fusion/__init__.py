"""
VERTEX Phase D4: Multimodal Evidence-Aware Fusion Package.

The fusion package is intentionally lightweight at import time.  The current
production deployment integrates the forensic LightGBM model, while the
semantic transformer/fusion service remains optional.  Keeping the heavyweight
service imports lazy prevents the FastAPI application from requiring
``transformers``/PyTorch just to import the risk engine.
"""

from __future__ import annotations

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
from app.ml.fusion.calibrator import FusionCalibrator

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


def __getattr__(name: str):
    """Load the heavyweight semantic/fusion service only when explicitly used."""
    if name in {
        "MultimodalFusionService",
        "get_fusion_service",
        "FUSION_MODEL_VERSION",
    }:
        from app.ml.fusion.service import (
            MultimodalFusionService,
            get_fusion_service,
            FUSION_MODEL_VERSION,
        )
        return {
            "MultimodalFusionService": MultimodalFusionService,
            "get_fusion_service": get_fusion_service,
            "FUSION_MODEL_VERSION": FUSION_MODEL_VERSION,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
