"""Risk engine endpoint.

POST /api/emails/{id}/risk — compute full risk assessment
GET  /api/emails/{id}/risk  — retrieve risk assessment
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.attachment_analyzer import analyze_attachments
from ..forensics.domain_intel import analyze_domain, extract_domains_from_headers
from ..forensics.ip_intelligence import analyze_ips, extract_ips_from_headers
from ..forensics.received_analyzer import parse_received_headers
from ..engine import get_canonical_risk_engine
from ..forensics.spf_analyzer import analyze_spf
from ..forensics.dkim_analyzer import analyze_dkim
from ..forensics.dmarc_analyzer import analyze_dmarc, extract_domain_from_address
from ..forensics.url_analyzer import analyze_urls, extract_urls_from_email
from ..ml.classifier import get_classifier
from ..models import Email
from ..utils import get_headers_dict
from ..engine.response_policy import evaluate_risk_assessment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["risk"])


class ResponseRecommendationOut(BaseModel):
    recommended_action: str
    approval_required: bool
    reversible: bool
    rationale: str
    severity: str
    risk_score: float
    confidence: float
    uncertainty: float
    evidence_quality: str
    policy_version: str = "5.1.0"


class SignalContributionOut(BaseModel):
    category: str
    signal: str
    raw_value: float
    weight: float
    contribution: float
    description: str
    confidence: str


class RiskAssessmentOut(BaseModel):
    email_id: int
    score: float
    level: str
    category_scores: dict[str, float] = Field(default_factory=dict)
    contributions: list[SignalContributionOut] = Field(default_factory=list)
    summary: str = ""
    limitations: list[str] = Field(default_factory=list)

    # Canonical Phase D5 fields
    risk_score: float | None = None
    severity: str | None = None
    threat_probabilities: dict[str, float] = Field(default_factory=dict)
    predicted_threat_label: str | None = None
    confidence: float | None = None
    uncertainty: float | None = None
    evidence_quality: dict[str, Any] | None = None
    model_evidence: dict[str, Any] | None = None
    category_caps: dict[str, float] = Field(default_factory=dict)
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""
    engine_version: str = "5.0.0"
    feature_version: str = "1.0.0"
    rule_set_version: str = "2026.1"

    # D5.1 Response Policy fields
    response_recommendation: ResponseRecommendationOut | None = None


def _run_risk_assessment(email_id: int, email_record: Email) -> RiskAssessmentOut:
    """Run the complete risk assessment pipeline."""
    headers = get_headers_dict(email_record.headers)
    from_domain = extract_domain_from_address(email_record.sender) if email_record.sender else None
    raw_bytes = email_record.raw_payload.raw_bytes if hasattr(email_record, "raw_payload") and email_record.raw_payload else None

    spf = analyze_spf(headers=headers, email_sender_domain=from_domain)
    dkim_results = analyze_dkim(headers=headers, raw_email_bytes=raw_bytes, email_sender_domain=from_domain)
    dkim_first = dkim_results[0] if dkim_results else None
    spf_envelope = spf.domain if spf.domain != from_domain else None
    dmarc = analyze_dmarc(
        email_sender_domain=from_domain, spf_result=spf.result, spf_envelope_domain=spf_envelope,
        dkim_result=dkim_first.result if dkim_first else None, dkim_domain=dkim_first.domain if dkim_first else None,
    )
    received = parse_received_headers(headers)
    ips = extract_ips_from_headers(headers)
    ip_analyses = analyze_ips(ips)
    domains = extract_domains_from_headers(headers)
    domain_analyses = [analyze_domain(d).to_dict() for d in domains]
    urls = extract_urls_from_email(body_text=email_record.body_text, body_html=email_record.body_html)
    url_analyses = [ua.to_dict() for ua in analyze_urls(urls)]
    att_dicts = [{"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256} for a in email_record.attachments]
    att_analyses = [aa.to_dict() for aa in analyze_attachments(att_dicts)]

    classifier = get_classifier()
    ml_result = classifier.classify(
        subject=email_record.subject, sender=email_record.sender, sender_name=email_record.sender_name,
        body_text=email_record.body_text, body_html=email_record.body_html,
        spf_result=spf.result, dkim_result=dkim_first.result if dkim_first else None,
    )

    engine = get_canonical_risk_engine()
    assessment = engine.assess(
        ml_label=ml_result.label, ml_confidence=ml_result.confidence, ml_risk_score=ml_result.risk_score,
        ml_signals=ml_result.signals, ml_signal_details=ml_result.signal_details,
        spf_result=spf.result, dkim_result=dkim_first.result if dkim_first else None, dmarc_result=dmarc.result,
        spf_domain=spf.domain, dkim_domain=dkim_first.domain if dkim_first else None,
        sender=email_record.sender, sender_name=email_record.sender_name, reply_to=email_record.reply_to,
        domain_analyses=domain_analyses, url_analyses=url_analyses, attachment_analyses=att_analyses,
        received_anomalies=received.anomalies, total_hops=received.total_hops, ip_analyses=[ia.to_dict() for ia in ip_analyses],
        subject=email_record.subject, body=email_record.body_text or email_record.body_html,
    )

    # D5.1: Generate response policy recommendation
    recommendation = evaluate_risk_assessment(assessment)

    return RiskAssessmentOut(
        email_id=email_id,
        **assessment.to_dict(),
        response_recommendation=ResponseRecommendationOut(
            recommended_action=recommendation.recommended_action.value,
            approval_required=recommendation.approval_required,
            reversible=recommendation.reversible,
            rationale=recommendation.rationale,
            severity=recommendation.severity,
            risk_score=recommendation.risk_score,
            confidence=recommendation.confidence,
            uncertainty=recommendation.uncertainty,
            evidence_quality=recommendation.evidence_quality,
            policy_version=recommendation.policy_version.value,
        ),
    )


@router.post("/{email_id}/risk", response_model=RiskAssessmentOut)
def compute_risk(email_id: int, db: Annotated[Session, Depends(get_db)]):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    try:
        return _run_risk_assessment(email_id, email_record)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Risk assessment failed for email %d", email_id)
        raise HTTPException(status_code=500, detail=f"Risk assessment failed: {type(e).__name__}: {e}")


@router.get("/{email_id}/risk", response_model=RiskAssessmentOut)
def get_risk(email_id: int, db: Annotated[Session, Depends(get_db)]):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    return _run_risk_assessment(email_id, email_record)
