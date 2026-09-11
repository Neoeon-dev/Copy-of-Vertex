"""Risk Engine — weighted multi-signal scoring with explainable breakdown.

Combines signals from ALL analysis modules into a single 0–100 risk score
with a full breakdown showing how each signal contributed.

Signal Categories and Default Weights:
  1. ML Classification      (25%) — model prediction confidence
  2. Authentication          (20%) — SPF / DKIM / DMARC failures
  3. Identity Mismatch       (10%) — display name vs address, Reply-To spoofing
  4. Domain Intelligence     (10%) — lookalikes, homoglyphs, suspicious TLDs
  5. URL Analysis            (10%) — IP URLs, shorteners, suspicious paths
  6. Attachment Risk         (10%) — dangerous extensions, double extensions
  7. Header Anomalies        (10%) — received-path anomalies, missing headers
  8. Infrastructure           (5%) — GeoIP reputation signals

Every score has an explainable breakdown:
  FACT → OBSERVATION → INFERENCE → CONFIDENCE

The engine never claims:
  - exact attacker location
  - that one signal proves fraud
  - unrealistic accuracy
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Risk levels ──────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _score_to_level(score: float) -> RiskLevel:
    """Convert a 0–100 score to a risk level."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ── Default weights ──────────────────────────────────────────────────

DEFAULT_WEIGHTS: dict[str, float] = {
    "ml_classification": 0.25,
    "authentication": 0.20,
    "identity_mismatch": 0.10,
    "domain_intelligence": 0.10,
    "url_analysis": 0.10,
    "attachment_risk": 0.10,
    "header_anomalies": 0.10,
    "infrastructure": 0.05,
}


# ── Signal breakdown ─────────────────────────────────────────────────


@dataclass
class SignalContribution:
    """One signal's contribution to the risk score."""

    category: str  # e.g. "authentication", "ml_classification"
    signal: str  # e.g. "spf_fail", "credential_request"
    raw_value: float  # 0.0 – 1.0 from the source module
    weight: float  # weight of this category (0.0 – 1.0)
    contribution: float  # raw_value * category_weight * signal_fraction
    description: str  # human-readable explanation
    confidence: str = "observed"  # fact | observed | inference

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "signal": self.signal,
            "raw_value": round(self.raw_value, 3),
            "weight": round(self.weight, 3),
            "contribution": round(self.contribution, 3),
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class RiskAssessment:
    """Complete risk assessment with explainable breakdown."""

    score: float = 0.0  # 0 – 100
    level: str = RiskLevel.LOW.value
    category_scores: dict[str, float] = field(default_factory=dict)  # 0 – 100 per category
    contributions: list[SignalContribution] = field(default_factory=list)
    summary: str = ""
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "level": self.level,
            "category_scores": {k: round(v, 1) for k, v in self.category_scores.items()},
            "contributions": [c.to_dict() for c in self.contributions],
            "summary": self.summary,
            "limitations": self.limitations,
        }


# ── Risk Engine ──────────────────────────────────────────────────────


class RiskEngine:
    """Computes a weighted multi-signal risk score with full explainability."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or dict(DEFAULT_WEIGHTS)
        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            logger.warning(
                "Risk weights sum to %.3f (expected 1.0). Normalizing.", total
            )
            for k in self.weights:
                self.weights[k] /= total

    def assess(
        self,
        # ML results
        ml_label: str | None = None,
        ml_confidence: float = 0.0,
        ml_risk_score: float = 0.0,
        ml_signals: dict[str, float] | None = None,
        ml_signal_details: dict[str, str] | None = None,
        # Authentication
        spf_result: str | None = None,
        dkim_result: str | None = None,
        dmarc_result: str | None = None,
        spf_domain: str | None = None,
        dkim_domain: str | None = None,
        # Identity
        sender: str | None = None,
        sender_name: str | None = None,
        reply_to: str | None = None,
        # Domain
        domain_analyses: list[dict[str, Any]] | None = None,
        # URLs
        url_analyses: list[dict[str, Any]] | None = None,
        # Attachments
        attachment_analyses: list[dict[str, Any]] | None = None,
        # Received headers
        received_anomalies: list[str] | None = None,
        total_hops: int = 0,
        # IP/Infrastructure
        ip_analyses: list[dict[str, Any]] | None = None,
    ) -> RiskAssessment:
        """Compute the full risk assessment from all available signals.

        Each analysis module passes its results; the engine computes
        category scores, then the weighted total, then an explanation.
        """
        contributions: list[SignalContribution] = []
        category_scores: dict[str, float] = {}

        # ── 1. ML Classification ─────────────────────────────────────
        ml_score = self._score_ml(ml_label, ml_confidence, ml_risk_score, ml_signals, ml_signal_details, contributions)
        category_scores["ml_classification"] = ml_score

        # ── 2. Authentication ────────────────────────────────────────
        auth_score = self._score_authentication(spf_result, dkim_result, dmarc_result, contributions)
        category_scores["authentication"] = auth_score

        # ── 3. Identity Mismatch ─────────────────────────────────────
        identity_score = self._score_identity(sender, sender_name, reply_to, contributions)
        category_scores["identity_mismatch"] = identity_score

        # ── 4. Domain Intelligence ───────────────────────────────────
        domain_score = self._score_domains(domain_analyses, contributions)
        category_scores["domain_intelligence"] = domain_score

        # ── 5. URL Analysis ──────────────────────────────────────────
        url_score = self._score_urls(url_analyses, contributions)
        category_scores["url_analysis"] = url_score

        # ── 6. Attachment Risk ───────────────────────────────────────
        att_score = self._score_attachments(attachment_analyses, contributions)
        category_scores["attachment_risk"] = att_score

        # ── 7. Header Anomalies ──────────────────────────────────────
        header_score = self._score_headers(received_anomalies, total_hops, contributions)
        category_scores["header_anomalies"] = header_score

        # ── 8. Infrastructure ────────────────────────────────────────
        infra_score = self._score_infrastructure(ip_analyses, contributions)
        category_scores["infrastructure"] = infra_score

        # ── Compute weighted total ───────────────────────────────────
        raw_score = sum(
            category_scores.get(cat, 0.0) * weight
            for cat, weight in self.weights.items()
        )
        final_score = min(100.0, max(0.0, raw_score))
        level = _score_to_level(final_score)

        # ── Build summary ────────────────────────────────────────────
        top_signals = sorted(contributions, key=lambda c: c.contribution, reverse=True)[:5]
        summary_parts = [f"Risk level: {level.value} ({final_score:.0f}/100)."]
        if top_signals:
            summary_parts.append(
                "Top risk factors: "
                + ", ".join(f"{s.signal.replace('_', ' ')} ({s.contribution:.1f})" for s in top_signals)
                + "."
            )

        # ── Limitations ──────────────────────────────────────────────
        limitations = [
            "Risk score is an inference, not a definitive verdict.",
            "No single signal alone determines the classification.",
            "Geolocation data reflects infrastructure location, not attacker identity.",
        ]
        if not ml_label:
            limitations.append("ML classification not available — score relies on rule-based signals only.")
        if spf_result == "NOT_CHECKED":
            limitations.append("SPF was not independently verified — relying on header claims only.")

        return RiskAssessment(
            score=final_score,
            level=level.value,
            category_scores=category_scores,
            contributions=contributions,
            summary=" ".join(summary_parts),
            limitations=limitations,
        )

    # ── Category scorers ─────────────────────────────────────────────

    def _score_ml(
        self,
        label: str | None,
        confidence: float,
        risk_score: float,
        signals: dict[str, float] | None,
        signal_details: dict[str, str] | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from ML classification results (0–100)."""
        if not label:
            contributions.append(SignalContribution(
                category="ml_classification",
                signal="no_ml_result",
                raw_value=0.0,
                weight=self.weights.get("ml_classification", 0),
                contribution=0.0,
                description="ML classification not available",
                confidence="inference",
            ))
            return 0.0

        # Map ML labels to risk scores
        label_risk = {"legitimate": 10, "suspicious": 40, "phishing": 80, "spammer": 60}
        base = label_risk.get(label, 30)
        # Scale by confidence
        ml_contribution = base * confidence
        ml_contribution = min(100.0, ml_contribution)

        contributions.append(SignalContribution(
            category="ml_classification",
            signal=f"ml_{label}",
            raw_value=risk_score,
            weight=self.weights.get("ml_classification", 0),
            contribution=ml_contribution * self.weights.get("ml_classification", 0),
            description=f"ML classified as '{label}' with {confidence:.0%} confidence",
            confidence="inference",
        ))

        # Individual ML signals
        if signals:
            for sig_name, sig_val in signals.items():
                if sig_val > 0:
                    detail = signal_details.get(sig_name, "") if signal_details else ""
                    contributions.append(SignalContribution(
                        category="ml_classification",
                        signal=sig_name,
                        raw_value=sig_val,
                        weight=self.weights.get("ml_classification", 0),
                        contribution=sig_val * 10 * self.weights.get("ml_classification", 0),
                        description=detail or f"{sig_name.replace('_', ' ')}: {sig_val:.0%}",
                        confidence="observed",
                    ))

        return ml_contribution

    def _score_authentication(
        self,
        spf: str | None,
        dkim: str | None,
        dmarc: str | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from authentication results (0–100)."""
        w = self.weights.get("authentication", 0)
        score = 0.0

        auth_results = {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
        }

        risk_values = {
            "PASS": 0,
            "NONE": 15,
            "SOFTFAIL": 40,
            "FAIL": 70,
            "TEMPERROR": 20,
            "PERMERROR": 50,
            "NOT_CHECKED": 10,
        }

        for mechanism, result in auth_results.items():
            if result is None:
                continue
            rv = risk_values.get(result, 10)
            score = max(score, rv)
            if rv > 0:
                contributions.append(SignalContribution(
                    category="authentication",
                    signal=f"{mechanism.lower()}_{result.lower().replace('-', '_')}",
                    raw_value=rv / 100,
                    weight=w,
                    contribution=rv * w,
                    description=f"{mechanism} result: {result}",
                    confidence="observed",
                ))

        return score

    def _score_identity(
        self,
        sender: str | None,
        sender_name: str | None,
        reply_to: str | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from identity mismatch signals (0–100)."""
        w = self.weights.get("identity_mismatch", 0)
        score = 0.0

        # Display name vs email domain mismatch
        if sender and sender_name:
            sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
            name_words = set(sender_name.lower().split())
            domain_label = sender_domain.split(".")[0] if sender_domain else ""
            if domain_label and not any(w in domain_label for w in name_words if len(w) > 2):
                mismatch_score = 50
                score = max(score, mismatch_score)
                contributions.append(SignalContribution(
                    category="identity_mismatch",
                    signal="display_name_mismatch",
                    raw_value=0.5,
                    weight=w,
                    contribution=mismatch_score * w,
                    description=f"Display name '{sender_name}' does not clearly match domain '{sender_domain}'",
                    confidence="observed",
                ))

        # Reply-To different from From
        if sender and reply_to:
            sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if sender_domain and reply_domain and sender_domain != reply_domain:
                spoof_score = 60
                score = max(score, spoof_score)
                contributions.append(SignalContribution(
                    category="identity_mismatch",
                    signal="reply_to_mismatch",
                    raw_value=0.6,
                    weight=w,
                    contribution=spoof_score * w,
                    description=f"Reply-To domain ({reply_domain}) differs from From domain ({sender_domain})",
                    confidence="observed",
                ))

        return score

    def _score_domains(
        self,
        domain_analyses: list[dict[str, Any]] | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from domain intelligence (0–100)."""
        if not domain_analyses:
            return 0.0

        w = self.weights.get("domain_intelligence", 0)
        max_score = 0.0

        for da in domain_analyses:
            domain = da.get("domain", "")
            risk = da.get("risk_score", 0)

            if da.get("has_homoglyphs"):
                s = 70
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="domain_intelligence",
                    signal="homoglyph_domain",
                    raw_value=0.7,
                    weight=w,
                    contribution=s * w,
                    description=f"Domain '{domain}' contains non-Latin homoglyphs",
                    confidence="observed",
                ))

            if da.get("suspicious_tld"):
                s = 30
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="domain_intelligence",
                    signal="suspicious_tld",
                    raw_value=0.3,
                    weight=w,
                    contribution=s * w,
                    description=f"Domain '{domain}' uses a suspicious TLD",
                    confidence="observed",
                ))

            for lookalike in da.get("lookalikes", []):
                brand = lookalike.get("brand_domain", "")
                dist = lookalike.get("distance", 99)
                s = max(40, 80 - dist * 10)
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="domain_intelligence",
                    signal="lookalike_domain",
                    raw_value=1.0 - dist / 10,
                    weight=w,
                    contribution=s * w,
                    description=f"Domain '{domain}' is a possible lookalike of '{brand}' (distance={dist})",
                    confidence="inference",
                ))

            if da.get("has_punycode"):
                s = 40
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="domain_intelligence",
                    signal="punycode_domain",
                    raw_value=0.4,
                    weight=w,
                    contribution=s * w,
                    description=f"Domain '{domain}' uses punycode encoding",
                    confidence="observed",
                ))

        return min(100.0, max_score)

    def _score_urls(
        self,
        url_analyses: list[dict[str, Any]] | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from URL analysis (0–100)."""
        if not url_analyses:
            return 0.0

        w = self.weights.get("url_analysis", 0)
        max_score = 0.0

        for ua in url_analyses:
            url = ua.get("url", "")

            if ua.get("is_ip_url"):
                s = 70
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="url_analysis",
                    signal="ip_based_url",
                    raw_value=0.7,
                    weight=w,
                    contribution=s * w,
                    description=f"URL uses IP address: {url}",
                    confidence="observed",
                ))

            if ua.get("is_shortener"):
                s = 35
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="url_analysis",
                    signal="url_shortener",
                    raw_value=0.35,
                    weight=w,
                    contribution=s * w,
                    description=f"URL uses shortener service: {url}",
                    confidence="observed",
                ))

            if ua.get("suspicious_path"):
                s = 45
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="url_analysis",
                    signal="suspicious_path",
                    raw_value=0.45,
                    weight=w,
                    contribution=s * w,
                    description=f"URL has suspicious path pattern: {url}",
                    confidence="observed",
                ))

            if ua.get("has_punycode"):
                s = 50
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="url_analysis",
                    signal="punycode_url",
                    raw_value=0.5,
                    weight=w,
                    contribution=s * w,
                    description=f"URL uses punycode: {url}",
                    confidence="observed",
                ))

        return min(100.0, max_score)

    def _score_attachments(
        self,
        attachment_analyses: list[dict[str, Any]] | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from attachment analysis (0–100)."""
        if not attachment_analyses:
            return 0.0

        w = self.weights.get("attachment_risk", 0)
        max_score = 0.0

        for aa in attachment_analyses:
            filename = aa.get("filename", "unknown")

            if aa.get("has_double_extension"):
                s = 85
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="attachment_risk",
                    signal="double_extension",
                    raw_value=0.85,
                    weight=w,
                    contribution=s * w,
                    description=f"Attachment '{filename}' has double extension (possible disguise)",
                    confidence="observed",
                ))

            if aa.get("is_dangerous_extension"):
                s = 70
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="attachment_risk",
                    signal="dangerous_extension",
                    raw_value=0.7,
                    weight=w,
                    contribution=s * w,
                    description=f"Attachment '{filename}' has a dangerous file extension",
                    confidence="observed",
                ))

            if aa.get("mime_mismatch"):
                s = 50
                max_score = max(max_score, s)
                contributions.append(SignalContribution(
                    category="attachment_risk",
                    signal="mime_mismatch",
                    raw_value=0.5,
                    weight=w,
                    contribution=s * w,
                    description=f"Attachment '{filename}' MIME type does not match extension",
                    confidence="observed",
                ))

        return min(100.0, max_score)

    def _score_headers(
        self,
        anomalies: list[str] | None,
        total_hops: int,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from header anomalies (0–100)."""
        w = self.weights.get("header_anomalies", 0)
        score = 0.0

        if anomalies:
            for anomaly in anomalies:
                if anomaly == "no_received_headers":
                    s = 30
                    score = max(score, s)
                    contributions.append(SignalContribution(
                        category="header_anomalies",
                        signal="no_received_headers",
                        raw_value=0.3,
                        weight=w,
                        contribution=s * w,
                        description="No Received headers found — possible header stripping",
                        confidence="inference",
                    ))
                elif anomaly == "non_monotonic_timestamps":
                    s = 60
                    score = max(score, s)
                    contributions.append(SignalContribution(
                        category="header_anomalies",
                        signal="timestamp_anomaly",
                        raw_value=0.6,
                        weight=w,
                        contribution=s * w,
                        description="Received headers have non-monotonic timestamps — possible forgery",
                        confidence="inference",
                    ))
                elif anomaly == "unusually_many_hops":
                    s = 25
                    score = max(score, s)
                    contributions.append(SignalContribution(
                        category="header_anomalies",
                        signal="many_hops",
                        raw_value=0.25,
                        weight=w,
                        contribution=s * w,
                        description="Unusually many relay hops detected",
                        confidence="observation",
                    ))
                elif anomaly == "only_one_hop":
                    s = 15
                    score = max(score, s)
                    contributions.append(SignalContribution(
                        category="header_anomalies",
                        signal="single_hop",
                        raw_value=0.15,
                        weight=w,
                        contribution=s * w,
                        description="Only one Received hop — email may originate from this host",
                        confidence="observation",
                    ))

        return min(100.0, score)

    def _score_infrastructure(
        self,
        ip_analyses: list[dict[str, Any]] | None,
        contributions: list[SignalContribution],
    ) -> float:
        """Score from infrastructure / IP intelligence (0–100)."""
        if not ip_analyses:
            return 0.0

        w = self.weights.get("infrastructure", 0)
        score = 0.0

        for ip_data in ip_analyses:
            ip = ip_data.get("ip", "")
            warnings = ip_data.get("warnings", [])

            # Many warnings per IP is suspicious
            if len(warnings) >= 3:
                s = 30
                score = max(score, s)
                contributions.append(SignalContribution(
                    category="infrastructure",
                    signal="ip_warnings",
                    raw_value=0.3,
                    weight=w,
                    contribution=s * w,
                    description=f"IP {ip} has {len(warnings)} intelligence warnings",
                    confidence="observation",
                ))

        return min(100.0, score)


# ── Singleton ────────────────────────────────────────────────────────

_engine: RiskEngine | None = None


def get_risk_engine() -> RiskEngine:
    global _engine
    if _engine is None:
        _engine = RiskEngine()
    return _engine
