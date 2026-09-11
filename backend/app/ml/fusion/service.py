"""
Production Multimodal Fusion Service for VERTEX (Phase D4).
Unifies Forensic Tabular LightGBM (D2) and Semantic Transformer DistilBERT (D3)
with dynamic evidence-quality weighting and uncertainty escalation.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from app.data.schema import CanonicalEmailRecord
from app.features.extractor import ForensicFeatureExtractor
from app.parsers.mime_parser import parse_email
from app.ml.version import TARGET_CLASSES, INT_TO_LABEL
from app.ml.models.forensic_service import (
    ForensicTabularService,
    get_forensic_service,
    ForensicPrediction,
)
from app.ml.semantic.service import SemanticInferenceService
from app.ml.fusion.schemas import (
    EvidenceQuality,
    FusionPrediction,
    FusionStrategy,
)
from app.ml.fusion.evidence_quality import EvidenceQualityAnalyzer
from app.ml.fusion.fusion import (
    EvidenceAwareFusionEngine,
    SmoothEvidenceRouter,
)

logger = logging.getLogger(__name__)

FUSION_MODEL_VERSION = "1.0.0"


class MultimodalFusionService:
    """
    Production-grade inference service hosting both forensic tabular and semantic transformer models,
    evaluating observable evidence quality, and computing calibrated multimodal threat intelligence.
    """

    def __init__(
        self,
        forensic_service: Optional[ForensicTabularService] = None,
        semantic_service: Optional[SemanticInferenceService] = None,
        strategy: FusionStrategy = FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED,
        forensic_model_dir: Optional[str] = None,
        semantic_model_dir: Optional[str] = None,
    ) -> None:
        self.model_version = FUSION_MODEL_VERSION

        # 1. Forensic Tabular Service (D2)
        if forensic_service is not None:
            self.forensic_service = forensic_service
        else:
            self.forensic_service = get_forensic_service(model_dir=forensic_model_dir)

        # 2. Semantic NLP Service (D3)
        if semantic_service is not None:
            self.semantic_service = semantic_service
        else:
            sem_dir = semantic_model_dir or os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../../models/semantic/v1")
            )
            if not os.path.exists(sem_dir):
                sem_dir = os.path.abspath("models/semantic/v1")
            self.semantic_service = SemanticInferenceService(model_dir=sem_dir)

        # 3. Evidence Quality Analyzer & Fusion Engine
        self.quality_analyzer = EvidenceQualityAnalyzer()
        self.fusion_engine = EvidenceAwareFusionEngine(strategy=strategy)
        self.extractor: Optional[ForensicFeatureExtractor] = None

    def analyze_email(
        self,
        raw_bytes: Optional[bytes] = None,
        record: Optional[CanonicalEmailRecord] = None,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        features: Optional[Dict[str, float]] = None,
        strategy: Optional[FusionStrategy] = None,
    ) -> FusionPrediction:
        """
        Performs full end-to-end multimodal threat intelligence analysis on an email.
        """
        start_time = time.perf_counter()

        subj = subject
        body_text = body
        feat_dict = features
        forensic_res: Optional[ForensicPrediction] = None

        # 1. Resolve components from raw_bytes if supplied
        if raw_bytes is not None:
            try:
                parsed = parse_email(raw_bytes)
                subj = subj if subj is not None else parsed.subject
                body_text = body_text if body_text is not None else parsed.body_text
            except Exception as e:
                logger.warning(f"Failed to parse MIME raw bytes: {e}")

            if feat_dict is None:
                if self.extractor is None:
                    self.extractor = ForensicFeatureExtractor()
                vec = self.extractor.extract_from_raw_bytes(raw_bytes)
                feat_dict = vec.features

        # 2. Resolve components from CanonicalEmailRecord if supplied
        if record is not None:
            subj = subj if subj is not None else record.subject
            body_text = body_text if body_text is not None else record.body
            if feat_dict is None:
                if self.extractor is None:
                    self.extractor = ForensicFeatureExtractor()
                if hasattr(self.extractor, "extract_from_record"):
                    vec = self.extractor.extract_from_record(record)
                else:
                    vec = self.extractor.extract_from_canonical_record(record)
                feat_dict = vec.features

        # 3. Obtain Forensic Tabular Prediction (D2)
        if feat_dict is not None:
            forensic_res = self.forensic_service.predict_features(feat_dict)
            evidence_quality = self.quality_analyzer.analyze_features(feat_dict)
        else:
            # Degraded/text-only input without tabular features
            evidence_quality = self.quality_analyzer.analyze_raw(subject=subj, body=body_text)
            dummy_feats = {fname: -1.0 for fname in self.quality_analyzer.feature_names}
            forensic_res = self.forensic_service.predict_features(dummy_feats)

        p_d2 = np.array([
            forensic_res.probabilities["legitimate"],
            forensic_res.probabilities["spam"],
            forensic_res.probabilities["phishing"],
        ], dtype=np.float64)

        # 4. Obtain Semantic NLP Prediction (D3)
        semantic_res = self.semantic_service.predict_email(subj, body_text)
        p_d3 = np.array([
            semantic_res["probabilities"]["legitimate"],
            semantic_res["probabilities"]["spam"],
            semantic_res["probabilities"]["phishing"],
        ], dtype=np.float64)

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # 5. Fuse Modalities
        return self.fusion_engine.predict(
            p_d2=p_d2,
            p_d3=p_d3,
            evidence_quality=evidence_quality,
            forensic_dict=forensic_res.to_dict() if forensic_res else None,
            semantic_dict=semantic_res,
            strategy=strategy,
            model_version=self.model_version,
            latency_ms=latency_ms,
        )

    def analyze_batch(
        self,
        emails: List[Tuple[Optional[str], Optional[str], Optional[Dict[str, float]]]],
        batch_size: int = 64,
        strategy: Optional[FusionStrategy] = None,
    ) -> List[FusionPrediction]:
        """
        Runs batched multimodal inference on a list of (subject, body, features) tuples.
        """
        if not emails:
            return []

        results: List[FusionPrediction] = []
        for subj, b_text, feats in emails:
            pred = self.analyze_email(
                subject=subj,
                body=b_text,
                features=feats,
                strategy=strategy,
            )
            results.append(pred)

        return results


_FUSION_SERVICE_INSTANCE: Optional[MultimodalFusionService] = None


def get_fusion_service(
    forensic_model_dir: Optional[str] = None,
    semantic_model_dir: Optional[str] = None,
    strategy: FusionStrategy = FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED,
) -> MultimodalFusionService:
    """Retrieves or initializes the global singleton MultimodalFusionService."""
    global _FUSION_SERVICE_INSTANCE
    if _FUSION_SERVICE_INSTANCE is None or forensic_model_dir is not None:
        _FUSION_SERVICE_INSTANCE = MultimodalFusionService(
            strategy=strategy,
            forensic_model_dir=forensic_model_dir,
            semantic_model_dir=semantic_model_dir,
        )
    return _FUSION_SERVICE_INSTANCE
