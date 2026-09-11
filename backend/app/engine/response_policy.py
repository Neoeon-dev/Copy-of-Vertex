"""
VERTEX Phase D5.1 Response-Policy Safety Hardening.

Defines a strict architectural boundary between the D5 Canonical Forensic
Risk Engine (risk assessment) and Incident Response / Enforcement
(response recommendation).

The ResponsePolicy consumes a RiskAssessment and returns a ResponseRecommendation.
It MUST NOT directly execute enforcement actions.

Architecture:
  RiskAssessment
       ↓
  ResponsePolicy.evaluate()
       ↓
  ResponseRecommendation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from app.engine.schemas import RiskAssessment, RiskLevel, EvidenceQualityBreakdown


class RecommendedAction(str, Enum):
    """Conservative response action vocabulary. No irreversible automatic actions."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    WARN = "WARN"
    ANALYST_REVIEW = "ANALYST_REVIEW"
    PRIORITIZE_REVIEW = "PRIORITIZE_REVIEW"
    MANUAL_CONTAINMENT_REVIEW = "MANUAL_CONTAINMENT_REVIEW"


class ResponsePolicyVersion(str, Enum):
    """Explicit response-policy versioning, separate from risk engine version."""
    V5_1_0 = "5.1.0"


@dataclass(frozen=True)
class ResponseRecommendation:
    """
    Stable schema for response recommendations produced by the D5.1 policy layer.

    This dataclass is immutable and never contains executable enforcement
    directives. It is purely recommendatory and human-signed-off.
    """

    recommended_action: RecommendedAction
    approval_required: bool
    reversible: bool
    rationale: str
    severity: str
    risk_score: float
    confidence: float
    uncertainty: float
    evidence_quality: str
    policy_version: ResponsePolicyVersion = ResponsePolicyVersion.V5_1_0

    # Backward-compatible alias for recommended_action
    @property
    def action(self) -> str:
        return self.recommended_action.value


@dataclass
class ResponsePolicy:
    """
    Consumes a RiskAssessment and produces a ResponseRecommendation.

    This is the D5.1 architectural boundary: risk scoring is separated
    from operational enforcement. The policy layer recommends actions
    but does not execute them.
    """

    policy_version: ResponsePolicyVersion = ResponsePolicyVersion.V5_1_0

    # ── Core Evaluation ────────────────────────────────────────────

    def evaluate(self, assessment: RiskAssessment) -> ResponseRecommendation:  # type: ignore[override]
        """Map a RiskAssessment to a ResponseRecommendation."""
        # Extract core values
        risk_score = assessment.risk_score
        severity = assessment.severity
        confidence = assessment.confidence
        uncertainty = assessment.uncertainty
        eq_tier = assessment.evidence_quality.tier
        eq_overall = assessment.evidence_quality.overall
        tvd = assessment.model_evidence.disagreement
        predicted_label = assessment.predicted_threat_label

        # ── Build gating context ────────────────────────────────────

        # Confidence/uncertainty gating
        low_confidence = confidence < 0.50
        high_confidence = confidence >= 0.80

        # Evidence quality gating
        degraded_evidence = eq_tier in ("LOW", "DEGRADED")

        # Model disagreement gating
        significant_disagreement = tvd >= 0.35

        # ── Determine recommended action ─────────────────────────────

        # Start from severity base, then apply gating modifiers
        base_action = self._base_action_for_severity(severity)

        # Apply confidence gating: low confidence elevates review need
        if low_confidence and severity in ("CRITICAL", "HIGH"):
            # Even CRITICAL with low confidence = prioritized review, not auto-block
            base_action = self._elevate_for_low_confidence(base_action)

        # Apply evidence quality gating: degraded evidence cannot cause automatic enforcement
        if degraded_evidence and severity in ("CRITICAL", "HIGH"):
            base_action = self._apply_degraded_evidence_modifier(base_action)

        # Apply model disagreement: elevates uncertainty, promotes review
        if significant_disagreement and severity in ("HIGH", "CRITICAL"):
            base_action = self._apply_disagreement_modifier(base_action)

        # Final safety: no irreversible automatic action ever produced
        # Ensure reversible and approval_required are correct
        approval_required = self._requires_approval(base_action)
        reversible = self._is_reversible(base_action)

        # Generate rationale
        rationale = self._generate_rationale(
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            uncertainty=uncertainty,
            eq_tier=eq_tier,
            degraded_evidence=degraded_evidence,
            tvd=tvd,
            predicted_label=predicted_label,
            base_action=base_action,
        )

        return ResponseRecommendation(
            recommended_action=base_action,
            approval_required=approval_required,
            reversible=reversible,
            rationale=rationale,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            uncertainty=uncertainty,
            evidence_quality=eq_tier,
            policy_version=self.policy_version,
        )

    # ── Action determination helpers ────────────────────────────────

    def _base_action_for_severity(self, severity: str) -> RecommendedAction:
        """Base mapping from severity to recommended action."""
        if severity == "CRITICAL":
            return RecommendedAction.PRIORITIZE_REVIEW
        elif severity == "HIGH":
            return RecommendedAction.ANALYST_REVIEW
        elif severity == "MEDIUM":
            return RecommendedAction.WARN
        else:  # LOW
            return RecommendedAction.ALLOW

    def _requires_approval(self, action: RecommendedAction) -> bool:
        """Determine if this action requires explicit human approval."""
        # All containment-oriented actions require approval
        # ALLOW and MONITOR do not strictly require approval for delivery
        # but do for any containment-oriented decisions
        if action in (RecommendedAction.PRIORITIZE_REVIEW, RecommendedAction.MANUAL_CONTAINMENT_REVIEW):
            return True
        if action in (RecommendedAction.ANALYST_REVIEW, RecommendedAction.WARN):
            return True
        # ALLOW and MONITOR can be delivered without blocking approval
        # but approval_required is still true for transparency
        return True

    def _is_reversible(self, action: RecommendedAction) -> bool:
        """All D5.1 recommendations are reversible by definition."""
        return True

    def _elevate_for_low_confidence(self, action: RecommendedAction) -> RecommendedAction:
        """Elevate action when confidence is low, even for high severity."""
        # The 'action' here is the base action from severity mapping:
        # CRITICAL -> PRIORITIZE_REVIEW, HIGH -> ANALYST_REVIEW, MEDIUM -> WARN, LOW -> ALLOW
        # CRITICAL + low confidence → PRIORITIZE_REVIEW (already elevated)
        # HIGH + low confidence → ANALYST_REVIEW (emphasize evidence acquisition)
        # MEDIUM + low confidence → WARN
        # LOW + low confidence → MONITOR
        if action == RecommendedAction.PRIORITIZE_REVIEW:
            return RecommendedAction.PRIORITIZE_REVIEW
        if action == RecommendedAction.ANALYST_REVIEW:
            return RecommendedAction.ANALYST_REVIEW
        if action == RecommendedAction.WARN:
            return RecommendedAction.WARN
        return RecommendedAction.MONITOR

    def _apply_degraded_evidence_modifier(self, action: RecommendedAction) -> RecommendedAction:
        """When evidence is degraded, promote review and recommend evidence acquisition."""
        if action == RecommendedAction.PRIORITIZE_REVIEW:
            return RecommendedAction.PRIORITIZE_REVIEW
        if action == RecommendedAction.ANALYST_REVIEW:
            return RecommendedAction.ANALYST_REVIEW
        if action == RecommendedAction.WARN:
            return RecommendedAction.WARN
        return RecommendedAction.MONITOR

    def _apply_disagreement_modifier(self, action: RecommendedAction) -> RecommendedAction:
        """When models disagree, elevate to analyst review."""
        if action == RecommendedAction.PRIORITIZE_REVIEW:
            return RecommendedAction.PRIORITIZE_REVIEW
        if action == RecommendedAction.ANALYST_REVIEW:
            return RecommendedAction.ANALYST_REVIEW
        if action == RecommendedAction.WARN:
            return RecommendedAction.WARN
        return RecommendedAction.MONITOR

    def _generate_rationale(
        self,
        severity: str,
        risk_score: float,
        confidence: float,
        uncertainty: float,
        eq_tier: str,
        degraded_evidence: bool,
        tvd: float,
        predicted_label: str,
        base_action: RecommendedAction,
    ) -> str:
        """Generate a concise explanation for the recommendation."""
        parts: List[str] = []

        # Severity and risk score
        parts.append(
            f"Forensic Risk: {severity} ({risk_score:.1f}/100)"
        )

        # Confidence/uncertainty
        parts.append(
            f"Decision Confidence: {confidence:.2f}, Uncertainty: {uncertainty:.2f}"
        )

        # Evidence quality
        if degraded_evidence:
            parts.append(
                f"Evidence Quality: {eq_tier} (degraded; limited forensic data available)."
            )
        else:
            parts.append(
                f"Evidence Quality: {eq_tier}."
            )

        # Model disagreement
        if tvd >= 0.35:
            parts.append(
                f"Model Disagreement: TVD={tvd:.2f} between forensic tabular and semantic text models."
            )

        # Action and approval
        action_name = base_action.value
        if base_action in (
            RecommendedAction.PRIORITIZE_REVIEW,
            RecommendedAction.MANUAL_CONTAINMENT_REVIEW,
        ):
            parts.append(
                f"Recommended Action: {action_name} — requires SOC analyst review. "
                f"Automatic enforcement is disabled by D5.1 policy."
            )
        elif base_action == RecommendedAction.ANALYST_REVIEW:
            parts.append(
                f"Recommended Action: {action_name}."
            )
        elif base_action == RecommendedAction.WARN:
            parts.append(
                f"Recommended Action: {action_name}."
            )
        else:  # ALLOW or MONITOR
            parts.append(
                f"Recommended Action: {action_name}."
            )

        # Never claim automatic enforcement
        parts.append(
            "Automatic enforcement disabled by D5.1 Response-Policy Safety Hardening. "
            "All recommendations require human SOC approval."
        )

        return " ".join(parts)


# Convenience function for quick evaluation
def evaluate_risk_assessment(
    assessment: RiskAssessment,
    policy_version: ResponsePolicyVersion = ResponsePolicyVersion.V5_1_0,
) -> ResponseRecommendation:
    """Quick evaluate a RiskAssessment into a ResponseRecommendation."""
    policy = ResponsePolicy(policy_version=policy_version)
    return policy.evaluate(assessment)