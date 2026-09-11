"""
Multimodal Evidence-Aware Fusion Engine for VERTEX (Phase D4).
Implements baseline fusion strategies, smooth evidence-weighted routing,
and learned meta-classification combining Forensic LightGBM (D2) and Semantic DistilBERT (D3).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
import joblib

from app.ml.version import TARGET_CLASSES, INT_TO_LABEL, LABEL_TO_INT
from app.ml.fusion.schemas import (
    EvidenceQuality,
    FusionPrediction,
    FusionStrategy,
    DisagreementCategory,
    QualityTier,
)
from app.ml.fusion.evidence_quality import EvidenceQualityAnalyzer

logger = logging.getLogger(__name__)


def sigmoid(x: float) -> float:
    """Numerically stable scalar sigmoid function."""
    if x >= 0:
        z = np.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = np.exp(x)
        return z / (1.0 + z)


class SmoothEvidenceRouter:
    """
    Computes smooth forensic modality weight alpha(Q) in [alpha_min, alpha_max] as a function of evidence quality Q in [0, 1].
    Avoids cliff-edge thresholding with continuous monotonic sigmoidal transition.
    """

    def __init__(
        self,
        alpha_min: float = 0.05,
        alpha_max: float = 0.70,
        q_midpoint: float = 0.35,
        steepness: float = 10.0,
    ) -> None:
        self.alpha_min = alpha_min
        self.alpha_max = alpha_max
        self.q_midpoint = q_midpoint
        self.steepness = steepness

        # Normalization constants to guarantee alpha(0) = alpha_min and alpha(1) = alpha_max
        self._s0 = sigmoid(steepness * (0.0 - q_midpoint))
        self._s1 = sigmoid(steepness * (1.0 - q_midpoint))
        self._denom = max(self._s1 - self._s0, 1e-6)

    def compute_alpha(self, q: float) -> float:
        """
        Calculates alpha for evidence quality q in [0, 1].
        alpha represents the weight allocated to the Forensic Tabular model.
        1 - alpha represents the weight allocated to the Semantic Transformer model.
        """
        q_clamped = min(max(float(q), 0.0), 1.0)
        s_q = sigmoid(self.steepness * (q_clamped - self.q_midpoint))
        normalized_s = (s_q - self._s0) / self._denom
        alpha = self.alpha_min + (self.alpha_max - self.alpha_min) * normalized_s
        return float(min(max(alpha, self.alpha_min), self.alpha_max))


class EvidenceAwareFusionEngine:
    """
    Unified fusion engine capable of executing any supported fusion strategy:
    - FORENSIC_ONLY (D2 alone)
    - SEMANTIC_ONLY (D3 alone)
    - EQUAL_AVERAGE (50/50 blend)
    - FIXED_WEIGHTED (constant alpha)
    - SMOOTH_EVIDENCE_WEIGHTED (dynamic alpha = f(Q))
    - LEARNED_LOGISTIC (trained meta-model)
    """

    def __init__(
        self,
        strategy: FusionStrategy = FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED,
        fixed_alpha: float = 0.55,
        router: Optional[SmoothEvidenceRouter] = None,
        confidence_threshold: float = 0.60,
    ) -> None:
        self.strategy = strategy
        self.fixed_alpha = fixed_alpha
        self.router = router or SmoothEvidenceRouter()
        self.confidence_threshold = confidence_threshold
        self.learned_model: Optional[Any] = None
        self.quality_analyzer = EvidenceQualityAnalyzer()

    def fuse_probabilities(
        self,
        p_d2: np.ndarray,
        p_d3: np.ndarray,
        evidence_quality: EvidenceQuality,
        strategy: Optional[FusionStrategy] = None,
    ) -> Tuple[np.ndarray, float]:
        """
        Fuses forensic probability vector p_d2 and semantic probability vector p_d3.
        Returns: (fused_prob_vector, alpha_used)
        """
        strat = strategy or self.strategy

        # Ensure valid float arrays of shape (3,)
        p_d2 = np.asarray(p_d2, dtype=np.float64)
        p_d3 = np.asarray(p_d3, dtype=np.float64)

        # Normalize inputs if necessary
        if p_d2.sum() > 0:
            p_d2 = p_d2 / p_d2.sum()
        if p_d3.sum() > 0:
            p_d3 = p_d3 / p_d3.sum()

        if strat == FusionStrategy.FORENSIC_ONLY:
            return p_d2, 1.0
        elif strat == FusionStrategy.SEMANTIC_ONLY:
            return p_d3, 0.0
        elif strat == FusionStrategy.EQUAL_AVERAGE:
            p_fused = 0.5 * p_d2 + 0.5 * p_d3
            return p_fused / p_fused.sum(), 0.5
        elif strat == FusionStrategy.FIXED_WEIGHTED:
            a = self.fixed_alpha
            p_fused = a * p_d2 + (1.0 - a) * p_d3
            return p_fused / p_fused.sum(), a
        elif strat == FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED:
            alpha = self.router.compute_alpha(evidence_quality.overall_quality)
            p_fused = alpha * p_d2 + (1.0 - alpha) * p_d3
            return p_fused / p_fused.sum(), alpha
        elif strat == FusionStrategy.LEARNED_LOGISTIC:
            if self.learned_model is not None:
                feat_vec = self._build_meta_features(p_d2, p_d3, evidence_quality)
                p_fused = self.learned_model.predict_proba(feat_vec.reshape(1, -1))[0]
                alpha = self.router.compute_alpha(evidence_quality.overall_quality)
                return p_fused / p_fused.sum(), alpha
            else:
                # Fallback to smooth evidence weighted if meta-model not fitted
                alpha = self.router.compute_alpha(evidence_quality.overall_quality)
                p_fused = alpha * p_d2 + (1.0 - alpha) * p_d3
                return p_fused / p_fused.sum(), alpha
        else:
            raise ValueError(f"Unsupported fusion strategy: {strat}")

    def _build_meta_features(
        self,
        p_d2: np.ndarray,
        p_d3: np.ndarray,
        evidence_quality: EvidenceQuality,
    ) -> np.ndarray:
        """Constructs meta-feature vector for learned fusion models."""
        alpha = self.router.compute_alpha(evidence_quality.overall_quality)
        dim_vals = [
            evidence_quality.dimension_scores.get(d, 0.0)
            for d in [
                "rfc822_headers",
                "auth_alignment",
                "relay_hops",
                "network_ip",
                "domain_reputation",
                "url_signals",
                "attachment_metadata",
                "body_content",
                "sender_envelope_alignment",
                "forensic_feature_density",
            ]
        ]
        disagree = 1.0 if np.argmax(p_d2) != np.argmax(p_d3) else 0.0

        meta_feats = np.concatenate([
            p_d2,                             # 3
            p_d3,                             # 3
            [evidence_quality.overall_quality], # 1
            [alpha],                          # 1
            [disagree],                       # 1
            dim_vals,                         # 10
            alpha * p_d2,                     # 3
            (1.0 - alpha) * p_d3,             # 3
        ])
        return meta_feats.astype(np.float32)

    def train_learned_fusion(
        self,
        val_p_d2: np.ndarray,
        val_p_d3: np.ndarray,
        val_eq: List[EvidenceQuality],
        y_val: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Trains the meta-classifier on validation split predictions.
        """
        n_samples = len(y_val)
        X_meta = []
        for i in range(n_samples):
            feat = self._build_meta_features(val_p_d2[i], val_p_d3[i], val_eq[i])
            X_meta.append(feat)
        X_meta = np.array(X_meta, dtype=np.float32)

        base_clf = LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )
        base_clf.fit(X_meta, y_val)
        self.learned_model = base_clf

        meta_probs = base_clf.predict_proba(X_meta)
        meta_preds = np.argmax(meta_probs, axis=1)
        train_acc = float(np.mean(meta_preds == y_val))

        logger.info(f"Fitted Learned Fusion Logistic Meta-Classifier (Val Acc: {train_acc:.4f})")
        return {
            "meta_features_dim": int(X_meta.shape[1]),
            "val_accuracy": round(train_acc, 4),
            "classes": [int(c) for c in base_clf.classes_],
        }

    def predict(
        self,
        p_d2: np.ndarray,
        p_d3: np.ndarray,
        evidence_quality: EvidenceQuality,
        forensic_dict: Optional[Dict[str, Any]] = None,
        semantic_dict: Optional[Dict[str, Any]] = None,
        strategy: Optional[FusionStrategy] = None,
        model_version: str = "1.0.0",
        latency_ms: float = 0.0,
    ) -> FusionPrediction:
        """
        Produces a complete, explainable FusionPrediction instance.
        """
        strat = strategy or self.strategy
        fused_probs, alpha = self.fuse_probabilities(p_d2, p_d3, evidence_quality, strategy=strat)

        pred_idx = int(np.argmax(fused_probs))
        pred_label = INT_TO_LABEL[pred_idx]
        conf = float(fused_probs[pred_idx])

        # Composite risk score: Phishing * 1.0 + Spam * 0.45
        risk = float(fused_probs[2] * 1.0 + fused_probs[1] * 0.45)
        risk = float(min(max(round(risk, 4), 0.0), 1.0))

        # Modality labels
        d2_idx = int(np.argmax(p_d2))
        d3_idx = int(np.argmax(p_d3))
        d2_label = INT_TO_LABEL[d2_idx]
        d3_label = INT_TO_LABEL[d3_idx]

        disagree_cat = DisagreementCategory.categorize(d2_label, d3_label).value

        # Escalation checks
        escalation = False
        reasons: List[str] = []

        if conf < self.confidence_threshold:
            escalation = True
            reasons.append(f"Low overall fusion confidence ({conf:.1%} < {self.confidence_threshold:.1%})")

        if d2_label != d3_label:
            if 0.20 <= evidence_quality.overall_quality <= 0.45:
                escalation = True
                reasons.append(
                    f"Modality conflict ({d2_label} vs {d3_label}) under intermediate evidence quality (Q={evidence_quality.overall_quality:.2f})"
                )
            if (d2_label == "phishing" and p_d2[2] >= 0.70 and d3_label == "legitimate") or (
                d3_label == "phishing" and p_d3[2] >= 0.70 and d2_label == "legitimate"
            ):
                escalation = True
                reasons.append("High-divergence conflict between Phishing and Legitimate across modalities")

        if fused_probs[2] >= 0.60:
            reasons.append(f"Elevated phishing probability ({fused_probs[2]:.1%}) warrants high-priority handling")

        # Explainable reasoning summary
        reasoning: List[str] = []
        reasoning.append(
            f"Evidence Quality Tier: {evidence_quality.tier} (Score: {evidence_quality.overall_quality:.2f}, Active Features: {evidence_quality.active_features_count}/{evidence_quality.total_features_count})."
        )
        reasoning.append(
            f"Modality Allocation: Forensic Weight={alpha:.1%}, Semantic Weight={(1.0 - alpha):.1%}."
        )
        if d2_label == d3_label:
            reasoning.append(
                f"Modality Concordance: Both forensic ({p_d2[d2_idx]:.1%}) and semantic ({p_d3[d3_idx]:.1%}) models agree on '{pred_label}'."
            )
        else:
            reasoning.append(
                f"Modality Disagreement ({disagree_cat}): Forensic model predicts '{d2_label}' ({p_d2[d2_idx]:.1%}) while Semantic model predicts '{d3_label}' ({p_d3[d3_idx]:.1%})."
            )
            if evidence_quality.overall_quality < 0.30:
                reasoning.append(
                    f"Resolution: Evidence quality is degraded ({evidence_quality.overall_quality:.2f}); semantic text understanding was prioritized over missing tabular artifacts."
                )
            else:
                reasoning.append(
                    f"Resolution: Evidence quality is sufficient ({evidence_quality.overall_quality:.2f}); weighted blend favors forensic authentication/header verification."
                )

        if evidence_quality.missing_evidence_flags:
            reasoning.append(
                f"Missing Evidence Detected: {', '.join(evidence_quality.missing_evidence_flags)}."
            )

        prob_dict = {
            "legitimate": round(float(fused_probs[0]), 4),
            "spam": round(float(fused_probs[1]), 4),
            "phishing": round(float(fused_probs[2]), 4),
        }

        return FusionPrediction(
            predicted_label=pred_label,
            predicted_index=pred_idx,
            confidence=round(conf, 4),
            probabilities=prob_dict,
            risk_score=risk,
            fusion_strategy=strat.value if isinstance(strat, FusionStrategy) else str(strat),
            alpha=round(alpha, 4),
            evidence_quality=evidence_quality,
            disagreement_category=disagree_cat,
            uncertainty_escalation=escalation,
            escalation_reasons=reasons,
            reasoning=reasoning,
            forensic_prediction=forensic_dict,
            semantic_prediction=semantic_dict,
            model_version=model_version,
            latency_ms=round(latency_ms, 2),
        )
