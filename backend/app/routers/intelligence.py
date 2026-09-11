"""
VERTEX Phase D6 — Threat Intelligence API Endpoints.

Analyst-safe APIs for threat intelligence queries.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..threat_intel import (
    IOC,
    IOCType,
    IOCValidationError,
    normalize_ioc,
    extract_iocs_from_email,
)
from ..threat_intel.schemas import (
    IntelligenceAssessment,
    ProviderName,
    Verdict,
    CacheStatus,
    ThreatIntelFinding,
    ProviderHealth,
)
from ..threat_intel.service import ThreatIntelServiceConfig, get_threat_intel_service
from ..models import Email
from ..utils import get_headers_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/intelligence", tags=["threat-intelligence"])


# ─── Request/Response Models ──────────────────────────────────────────

class IOCLookupRequest(BaseModel):
    """Request to look up an IOC."""
    value: str = Field(..., description="Raw IOC value")
    ioc_type: str | None = Field(None, description="IOC type hint (auto-detected if omitted)")
    source_location: str = Field("api", description="Source of the IOC")
    extraction_context: str = Field("", description="Additional context")


class IOCLookupResponse(BaseModel):
    """Response for IOC lookup."""
    assessment: IntelligenceAssessment
    ioc: dict[str, Any]


class EmailIntelligenceResponse(BaseModel):
    """Response for email intelligence analysis."""
    email_id: int
    assessment: IntelligenceAssessment
    extracted_iocs: list[dict[str, Any]]


class ProviderHealthResponse(BaseModel):
    """Provider health status."""
    providers: dict[str, dict[str, Any]]
    circuit_breakers: dict[str, dict[str, Any]]
    rate_limiters: dict[str, dict[str, Any]]
    cache: dict[str, Any]


# ─── Endpoints ────────────────────────────────────────────────────────

@router.get("/providers", response_model=list[str])
async def list_providers():
    """List available threat intelligence providers."""
    return ["openphish", "virustotal", "abuseipdb"]


@router.get("/health", response_model=ProviderHealthResponse)
async def get_intelligence_health():
    """Get health status for all threat intelligence components."""
    service = get_threat_intel_service()
    return ProviderHealthResponse(
        providers=service.get_provider_health(),
        circuit_breakers=service.get_circuit_breaker_stats(),
        rate_limiters=service.get_rate_limiter_stats(),
        cache=service.get_cache_stats(),
    )


@router.post("/lookup", response_model=IOCLookupResponse)
async def lookup_ioc(request: IOCLookupRequest):
    """
    Look up a single IOC across all enabled providers.
    
    This endpoint is safe — it only submits the normalized IOC value to
    external provider APIs. It never fetches URLs or resolves attacker-
    controlled domains.
    """
    try:
        ioc = normalize_ioc(
            value=request.value,
            ioc_type=IOCType(request.ioc_type) if request.ioc_type else None,
            source_location=request.source_location,
            extraction_context=request.extraction_context,
        )
    except IOCValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IOC: {e}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type: {e}")
    
    service = get_threat_intel_service()
    assessment = await service.lookup_ioc(ioc)
    
    return IOCLookupResponse(
        assessment=assessment,
        ioc=ioc.to_dict(),
    )


@router.post("/lookup/batch")
async def lookup_iocs_batch(
    values: list[str],
    ioc_type: str | None = None,
    source_location: str = "api",
):
    """Look up multiple IOCs with deduplication."""
    try:
        ioc_type_enum = IOCType(ioc_type) if ioc_type else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type: {ioc_type}")
    
    try:
        iocs = normalize_iocs(
            values=values,
            ioc_type=ioc_type_enum,
            source_location=source_location,
        )
    except IOCValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IOC: {e}")
    
    service = get_threat_intel_service()
    # For batch, we'll query each IOC individually (service handles deduplication)
    all_findings = []
    queried = []
    
    for ioc in iocs:
        assessment = await service.lookup_ioc(ioc)
        all_findings.extend(assessment.findings)
        queried.extend(assessment.queried_iocs)
    
    # Re-aggregate
    final_assessment = service._aggregator.aggregate(all_findings, queried)
    
    return {
        "assessment": final_assessment.to_dict(),
        "iocs": [ioc.to_dict() for ioc in iocs],
    }


@router.get("/email/{email_id}", response_model=EmailIntelligenceResponse)
async def get_email_intelligence(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Get threat intelligence for a specific email.
    
    Extracts IOCs from the email and queries all enabled providers.
    """
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    
    service = get_threat_intel_service()
    
    headers = get_headers_dict(email_record.headers)
    
    assessment = await service.analyze_email(
        headers=headers,
        body_text=email_record.body_text,
        body_html=email_record.body_html,
        attachments=[
            {"filename": a.filename, "sha256": a.sha256}
            for a in email_record.attachments
        ],
    )
    
    # Also return extracted IOCs for reference
    raw_iocs = extract_iocs_from_email(
        headers=headers,
        body_text=email_record.body_text,
        body_html=email_record.body_html,
        attachments=[
            {"filename": a.filename, "sha256": a.sha256}
            for a in email_record.attachments
        ],
    )
    
    return EmailIntelligenceResponse(
        email_id=email_id,
        assessment=assessment,
        extracted_iocs=[ioc.to_dict() for ioc in raw_iocs],
    )


@router.get("/ioc/{ioc_type}/{ioc_value}", response_model=IOCLookupResponse)
async def lookup_ioc_by_path(
    ioc_type: str,
    ioc_value: str,
    source_location: str = Query("api", description="Source location"),
):
    """
    Look up an IOC by path parameters.
    
    Example: GET /api/intelligence/ioc/IPV4/1.2.3.4
    """
    try:
        ioc_type_enum = IOCType(ioc_type.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported IOC type: {ioc_type}")
    
    try:
        ioc = normalize_ioc(
            value=ioc_value,
            ioc_type=ioc_type_enum,
            source_location=source_location,
        )
    except IOCValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IOC: {e}")
    
    service = get_threat_intel_service()
    assessment = await service.lookup_ioc(ioc)
    
    return IOCLookupResponse(
        assessment=assessment,
        ioc=ioc.to_dict(),
    )