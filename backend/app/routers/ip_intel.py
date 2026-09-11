"""IP intelligence endpoint.

POST /api/emails/{email_id}/ip-intel — analyze all IPs in an email
GET  /api/emails/{email_id}/ip-intel — retrieve IP analysis
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.ip_intelligence import analyze_ips, extract_ips_from_headers
from ..models import Email
from ..utils import get_headers_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["ip-intelligence"])


class GeoInfoOut(BaseModel):
    country_code: str | None = None
    country_name: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_radius_km: int | None = None


class ASNInfoOut(BaseModel):
    asn: int | None = None
    organization: str | None = None
    network: str | None = None


class IPIntelOut(BaseModel):
    ip: str
    is_public: bool | None = None
    is_private: bool | None = None
    is_reserved: bool | None = None
    geo: GeoInfoOut | None = None
    asn: ASNInfoOut | None = None
    warnings: list[str] = Field(default_factory=list)


class IPAnalysisOut(BaseModel):
    email_id: int
    ips: list[IPIntelOut] = Field(default_factory=list)
    total_ips: int = 0
    public_ips: int = 0
    private_ips: int = 0


def _build_ip_analysis(email_id: int, email_record: Email) -> IPAnalysisOut:
    headers = get_headers_dict(email_record.headers)
    ips = extract_ips_from_headers(headers)
    analyses = analyze_ips(ips)
    public_count = sum(1 for a in analyses if a.is_public)
    private_count = sum(1 for a in analyses if a.is_private)
    return IPAnalysisOut(
        email_id=email_id, ips=[IPIntelOut(**a.to_dict()) for a in analyses],
        total_ips=len(analyses), public_ips=public_count, private_ips=private_count,
    )


@router.post("/{email_id}/ip-intel", response_model=IPAnalysisOut)
def analyze_email_ips(email_id: int, db: Annotated[Session, Depends(get_db)]):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    return _build_ip_analysis(email_id, email_record)


@router.get("/{email_id}/ip-intel", response_model=IPAnalysisOut)
def get_email_ip_intel(email_id: int, db: Annotated[Session, Depends(get_db)]):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")
    return _build_ip_analysis(email_id, email_record)
