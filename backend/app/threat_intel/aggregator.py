"""
VERTEX Phase D6 — Intelligence Aggregator.

Aggregates findings from multiple threat intelligence providers into a unified
IntelligenceAssessment with provider agreement/disagreement tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.threat_intel.ioc import IOC
from app.threat_intel.providers.base import ThreatIntelProvider
from app.threat_intel.schemas import (
    IntelligenceAssessment,
    ThreatIntelFinding,
    Verdict,
    CacheStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class AggregationConfig:
    """Configuration for intelligence aggregation."""
    # Minimum providers required for agreement
    min_providers_for_agreement: int = 2
    # Confidence weights
    provider_reliability: dict[str, float] = field(default_factory=lambda: {
        "virustotal": 0.9,
        "abuseipdb": 0.8,
        "openphish": 0.7,
    })
    # Freshness decay (per hour)
    freshness_decay_per_hour: float = 0.02
    # Minimum confidence to consider a finding
    min_finding_confidence: float = 0.3
    # Treat UNKNOWN as neutral (not supporting or contradicting)
    unknown_is_neutral: bool = True


class IntelligenceAggregator:
    """
    Aggregates threat intelligence findings from multiple providers.
    
    Produces an IntelligenceAssessment with:
    - Per-IOC provider agreement/disagreement
    - Aggregated confidence considering provider reliability
    - Freshness scoring
    - Evidence quality assessment
    """
    
    def __init__(self, config: AggregationConfig | None = None):
        self.config = config or AggregationConfig()
    
    def aggregate(
        self,
        findings: list[ThreatIntelFinding],
        queried_iocs: list[dict[str, Any]] | None = None,
    ) -> IntelligenceAssessment:
        """
        Aggregate findings from multiple providers into an assessment.
        
        Args:
            findings: List of ThreatIntelFinding from all providers
            queried_iocs: Original IOCs that were queried (for provenance)
        
        Returns:
            IntelligenceAssessment with aggregated results
        """
        if not findings:
            return IntelligenceAssessment(
                queried_iocs=queried_iocs or [],
                findings=[],
                provider_summary={},
                evidence_quality="DEGRADED",
                explanation="No threat intelligence findings available",
            )
        
        # Group findings by IOC
        ioc_findings: dict[str, list[ThreatIntelFinding]] = {}
        for f in findings:
            key = f"{f.ioc_type}:{f.ioc_value}"
            if key not in ioc_findings:
                ioc_findings[key] = []
            ioc_findings[key].append(f)
        
        # Analyze each IOC
        provider_agreement: list[str] = []
        provider_disagreement: list[str] = []
        
        total_confidence = 0.0
        total_freshness = 0.0
        finding_count = 0
        
        for ioc_key, ioc_finding_list in ioc_findings.items():
            # Separate by verdict
            verdicts: dict[Verdict, list[ThreatIntelFinding]] = {
                Verdict.MALICIOUS: [],
                Verdict.SUSPICIOUS: [],
                Verdict.BENIGN: [],
                Verdict.UNKNOWN: [],
            }
            
            for f in ioc_finding_list:
                verdicts[f.verdict].append(f)
            
            # Check agreement/disagreement
            has_malicious = len(verdicts[Verdict.MALICIOUS]) > 0
            has_suspicious = len(verdicts[Verdict.SUSPICIOUS]) > 0
            has_benign = len(verdicts[Verdict.BENIGN]) > 0
            has_unknown = len(verdicts[Verdict.UNKNOWN]) > 0
            
            # Count providers with definitive verdicts (not UNKNOWN)
            definitive_providers = sum(
                len(v) for v in verdicts.values() if v and v[0].verdict != Verdict.UNKNOWN
            )
            
            # Agreement: multiple providers with same definitive verdict
            if definitive_providers >= self.config.min_providers_for_agreement:
                if has_malicious and len(verdicts[Verdict.MALICIOUS]) >= self.config.min_providers_for_agreement:
                    provider_agreement.append(f"{ioc_key}: MALICIOUS ({len(verdicts[Verdict.MALICIOUS])} providers)")
                elif has_suspicious and len(verdicts[Verdict.SUSPICIOUS]) >= self.config.min_providers_for_agreement:
                    provider_agreement.append(f"{ioc_key}: SUSPICIOUS ({len(verdicts[Verdict.SUSPICIOUS])} providers)")
                elif has_benign and len(verdicts[Verdict.BENIGN]) >= self.config.min_providers_for_agreement:
                    provider_agreement.append(f"{ioc_key}: BENIGN ({len(verdicts[Verdict.BENIGN])} providers)")
            
            # Disagreement: providers have conflicting definitive verdicts
            definitive_verdicts = []
            if has_malicious:
                definitive_verdicts.append("MALICIOUS")
            if has_suspicious:
                definitive_verdicts.append("SUSPICIOUS")
            if has_benign:
                definitive_verdicts.append("BENIGN")
            
            if len(definitive_verdicts) > 1:
                provider_disagreement.append(f"{ioc_key}: {', '.join(definitive_verdicts)}")
            
            # Aggregate confidence for this IOC
            ioc_confidence = self._compute_ioc_confidence(ioc_finding_list)
            total_confidence += ioc_confidence
            
            # Aggregate freshness for this IOC
            ioc_freshness = self._compute_ioc_freshness(ioc_finding_list)
            total_freshness += ioc_freshness
            
            finding_count += 1
        
        # Build provider summary
        provider_summary = self._build_provider_summary(findings)
        
        # Count verdicts
        malicious_count = sum(1 for f in findings if f.verdict == Verdict.MALICIOUS)
        suspicious_count = sum(1 for f in findings if f.verdict == Verdict.SUSPICIOUS)
        benign_count = sum(1 for f in findings if f.verdict == Verdict.BENIGN)
        unknown_count = sum(1 for f in findings if f.verdict == Verdict.UNKNOWN)
        unavailable_count = sum(1 for f in findings if f.cache_status == CacheStatus.UNAVAILABLE)
        
        # Overall confidence and freshness
        overall_confidence = total_confidence / finding_count if finding_count > 0 else 0.0
        overall_freshness = total_freshness / finding_count if finding_count > 0 else 0.0
        
        # Determine evidence quality
        evidence_quality = self._assess_evidence_quality(findings, provider_summary)
        
        # Generate explanation
        explanation = self._generate_explanation(
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            benign_count=benign_count,
            unknown_count=unknown_count,
            unavailable_count=unavailable_count,
            provider_agreement=provider_agreement,
            provider_disagreement=provider_disagreement,
        )
        
        return IntelligenceAssessment(
            queried_iocs=queried_iocs or [],
            findings=findings,
            provider_summary=provider_summary,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            benign_count=benign_count,
            unknown_count=unknown_count,
            unavailable_count=unavailable_count,
            confidence=round(overall_confidence, 4),
            freshness=round(overall_freshness, 4),
            provider_agreement=provider_agreement,
            provider_disagreement=provider_disagreement,
            evidence_quality=evidence_quality,
            explanation=explanation,
            provenance={
                "total_findings": len(findings),
                "unique_iocs": len(ioc_findings),
                "providers_queried": list(provider_summary.keys()),
            },
        )
    
    def _compute_ioc_confidence(self, findings: list[ThreatIntelFinding]) -> float:
        """Compute aggregated confidence for a single IOC across providers."""
        if not findings:
            return 0.0
        
        # Weight by provider reliability
        total_weight = 0.0
        weighted_confidence = 0.0
        
        for f in findings:
            provider = f.provider.value
            reliability = self.config.provider_reliability.get(provider, 0.5)
            
            # Only count findings with definitive verdicts
            if f.verdict != Verdict.UNKNOWN:
                weighted_confidence += f.confidence * reliability
                total_weight += reliability
        
        if total_weight == 0:
            return 0.0
        
        return min(1.0, weighted_confidence / total_weight)
    
    def _compute_ioc_freshness(self, findings: list[ThreatIntelFinding]) -> float:
        """Compute freshness score for a single IOC (0.0-1.0)."""
        if not findings:
            return 0.0
        
        now = datetime.now(timezone.utc)
        freshness_scores = []
        
        for f in findings:
            if f.cache_status == CacheStatus.LIVE:
                freshness_scores.append(1.0)
            elif f.cache_status == CacheStatus.CACHED:
                # Decay based on age
                age_hours = (now - f.queried_at).total_seconds() / 3600
                freshness = max(0.0, 1.0 - (age_hours * self.config.freshness_decay_per_hour))
                freshness_scores.append(freshness)
            elif f.cache_status == CacheStatus.STALE:
                freshness_scores.append(0.2)  # Low but not zero
            else:
                freshness_scores.append(0.0)
        
        return sum(freshness_scores) / len(freshness_scores) if freshness_scores else 0.0
    
    def _build_provider_summary(self, findings: list[ThreatIntelFinding]) -> dict[str, dict[str, Any]]:
        """Build per-provider statistics."""
        summary = {}
        
        for f in findings:
            provider = f.provider.value
            if provider not in summary:
                summary[provider] = {
                    "total": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "benign": 0,
                    "unknown": 0,
                    "unavailable": 0,
                    "cached": 0,
                    "live": 0,
                    "stale": 0,
                    "avg_confidence": 0.0,
                    "errors": 0,
                }
            
            s = summary[provider]
            s["total"] += 1
            
            if f.verdict == Verdict.MALICIOUS:
                s["malicious"] += 1
            elif f.verdict == Verdict.SUSPICIOUS:
                s["suspicious"] += 1
            elif f.verdict == Verdict.BENIGN:
                s["benign"] += 1
            elif f.verdict == Verdict.UNKNOWN:
                s["unknown"] += 1
            
            if f.cache_status == CacheStatus.UNAVAILABLE:
                s["unavailable"] += 1
            elif f.cache_status == CacheStatus.CACHED:
                s["cached"] += 1
            elif f.cache_status == CacheStatus.LIVE:
                s["live"] += 1
            elif f.cache_status == CacheStatus.STALE:
                s["stale"] += 1
            
            if f.error:
                s["errors"] += 1
            
            # Update running average confidence
            n = s["total"]
            s["avg_confidence"] = ((n - 1) * s["avg_confidence"] + f.confidence) / n
        
        return summary
    
    def _assess_evidence_quality(
        self,
        findings: list[ThreatIntelFinding],
        provider_summary: dict[str, dict[str, Any]],
    ) -> str:
        """Assess overall evidence quality."""
        if not findings:
            return "DEGRADED"
        
        total = len(findings)
        live = sum(1 for f in findings if f.cache_status == CacheStatus.LIVE)
        cached = sum(1 for f in findings if f.cache_status == CacheStatus.CACHED)
        stale = sum(1 for f in findings if f.cache_status == CacheStatus.STALE)
        unavailable = sum(1 for f in findings if f.cache_status == CacheStatus.UNAVAILABLE)
        definitive = sum(1 for f in findings if f.verdict != Verdict.UNKNOWN)
        
        live_ratio = live / total if total > 0 else 0
        definitive_ratio = definitive / total if total > 0 else 0
        provider_count = len(provider_summary)
        
        # Quality thresholds
        if live_ratio >= 0.8 and definitive_ratio >= 0.5 and provider_count >= 2:
            return "HIGH"
        elif live_ratio >= 0.5 and definitive_ratio >= 0.3 and provider_count >= 2:
            return "MEDIUM"
        elif definitive_ratio >= 0.2 and provider_count >= 1:
            return "LOW"
        else:
            return "DEGRADED"
    
    def _generate_explanation(
        self,
        malicious_count: int,
        suspicious_count: int,
        benign_count: int,
        unknown_count: int,
        unavailable_count: int,
        provider_agreement: list[str],
        provider_disagreement: list[str],
    ) -> str:
        """Generate human-readable explanation."""
        parts = []
        
        total_queried = malicious_count + suspicious_count + benign_count + unknown_count + unavailable_count
        
        parts.append(
            f"Threat intelligence analysis queried {total_queried} IOCs across multiple providers."
        )
        
        if malicious_count > 0:
            parts.append(f"{malicious_count} IOC(s) reported MALICIOUS.")
        if suspicious_count > 0:
            parts.append(f"{suspicious_count} IOC(s) reported SUSPICIOUS.")
        if benign_count > 0:
            parts.append(f"{benign_count} IOC(s) reported BENIGN.")
        if unknown_count > 0:
            parts.append(f"{unknown_count} IOC(s) have no intelligence (UNKNOWN).")
        if unavailable_count > 0:
            parts.append(f"{unavailable_count} IOC(s) could not be queried (UNAVAILABLE).")
        
        if provider_agreement:
            parts.append(f"Provider agreement on {len(provider_agreement)} IOC(s): {'; '.join(provider_agreement[:3])}.")
        
        if provider_disagreement:
            parts.append(f"Provider disagreement on {len(provider_disagreement)} IOC(s): {'; '.join(provider_disagreement[:3])}.")
        
        parts.append(
            "Intelligence is external evidence only. Does not modify forensic risk score. "
            "All response actions require human analyst approval per D5.1 policy."
        )
        
        return " ".join(parts)