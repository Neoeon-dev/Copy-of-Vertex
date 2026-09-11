"""Combined email analysis endpoint.

POST /api/emails/{id}/analyze-full — run the complete forensic pipeline
GET  /api/emails/{id}/analyze-full — retrieve full analysis results
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
from ..forensics.spf_analyzer import analyze_spf
from ..forensics.dkim_analyzer import analyze_dkim
from ..forensics.dmarc_analyzer import analyze_dmarc, extract_domain_from_address
from ..forensics.url_analyzer import analyze_urls, extract_urls_from_email
from ..engine import get_canonical_risk_engine
from ..models import Email
from ..utils import get_headers_dict
from ..engine.response_policy import evaluate_risk_assessment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["full-analysis"])


class AuthResultSimple(BaseModel):
    mechanism: str
    result: str
    domain: str | None = None
    details: str | None = None


class FullAnalysisOut(BaseModel):
    email_id: int
    subject: str | None = None
    sender: str | None = None
    spf: AuthResultSimple | None = None
    dkim: AuthResultSimple | None = None
    dmarc: AuthResultSimple | None = None
    total_hops: int = 0
    public_ips: list[str] = Field(default_factory=list)
    private_ips: list[str] = Field(default_factory=list)
    received_anomalies: list[str] = Field(default_factory=list)
    ip_analysis: list[dict[str, Any]] = Field(default_factory=list)
    domain_analysis: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    total_urls: int = 0
    attachment_analysis: list[dict[str, Any]] = Field(default_factory=list)
    overall_risk_score: float = 0.0
    response_recommendation: dict[str, Any] | None = None


@router.post("/{email_id}/analyze-full", response_model=FullAnalysisOut)
def run_full_analysis(email_id: int, db: Annotated[Session, Depends(get_db)]):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    try:
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
        domain_analyses = [analyze_domain(d) for d in domains]
        urls = extract_urls_from_email(body_text=email_record.body_text, body_html=email_record.body_html)
        url_analyses = analyze_urls(urls)
        att_dicts = [{"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256} for a in email_record.attachments]
        att_analyses = analyze_attachments(att_dicts)

        engine = get_canonical_risk_engine()
        assessment = engine.assess(
            spf_result=spf.result,
            dkim_result=dkim_first.result if dkim_first else None,
            dmarc_result=dmarc.result,
            spf_domain=spf.domain,
            dkim_domain=dkim_first.domain if dkim_first else None,
            sender=email_record.sender,
            sender_name=email_record.sender_name,
            reply_to=email_record.reply_to,
            domain_analyses=[da.to_dict() for da in domain_analyses],
            url_analyses=[ua.to_dict() for ua in url_analyses],
            attachment_analyses=[aa.to_dict() for aa in att_analyses],
            received_anomalies=received.anomalies,
            total_hops=received.total_hops,
            ip_analyses=[ia.to_dict() for ia in ip_analyses],
            subject=email_record.subject,
            body=email_record.body_text or email_record.body_html,
        )
        overall_risk = assessment.risk_score

        # D5.1: Generate response policy recommendation
        recommendation = evaluate_risk_assessment(assessment)

        return FullAnalysisOut(
            email_id=email_id, subject=email_record.subject, sender=email_record.sender,
            spf=AuthResultSimple(mechanism="SPF", result=spf.result, domain=spf.domain, details=spf.details),
            dkim=AuthResultSimple(mechanism="DKIM", result=dkim_first.result if dkim_first else "NONE", domain=dkim_first.domain if dkim_first else None, details=dkim_first.details if dkim_first else None),
            dmarc=AuthResultSimple(mechanism="DMARC", result=dmarc.result, domain=dmarc.domain, details=dmarc.details),
            total_hops=received.total_hops, public_ips=received.public_ips, private_ips=received.private_ips,
            received_anomalies=received.anomalies, ip_analysis=[ia.to_dict() for ia in ip_analyses],
            domain_analysis=[da.to_dict() for da in domain_analyses], urls=[ua.to_dict() for ua in url_analyses],
            total_urls=len(urls), attachment_analysis=[aa.to_dict() for aa in att_analyses],
            overall_risk_score=round(overall_risk, 3),
            response_recommendation={
                "recommended_action": recommendation.recommended_action.value,
                "approval_required": recommendation.approval_required,
                "reversible": recommendation.reversible,
                "rationale": recommendation.rationale,
                "severity": recommendation.severity,
                "risk_score": recommendation.risk_score,
                "confidence": recommendation.confidence,
                "uncertainty": recommendation.uncertainty,
                "evidence_quality": recommendation.evidence_quality,
                "policy_version": recommendation.policy_version.value,
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Full analysis failed for email %d", email_id)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {type(e).__name__}: {e}")


@router.get("/{email_id}/analyze-full", response_model=FullAnalysisOut)
def get_full_analysis(email_id: int, db: Annotated[Session, Depends(get_db)]):
    return run_full_analysis(email_id, db)
