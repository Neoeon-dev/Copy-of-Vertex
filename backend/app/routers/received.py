"""Received-header forensic analysis endpoint.

GET  /api/emails/{email_id}/received — get relay path analysis
POST /api/emails/{email_id}/received — run and return analysis
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.received_analyzer import ReceivedChainAnalysis, parse_received_headers
from ..models import Email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["received"])


# ── Response schemas ─────────────────────────────────────────────────


class ReceivedHopOut(BaseModel):
    position: int
    source_hostname: str | None = None
    source_ip: str | None = None
    source_is_public: bool | None = None
    destination_hostname: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    timestamp: str | None = None
    anomaly_indicators: list[str] = Field(default_factory=list)
    trust_level: str = "observed"


class ReceivedChainOut(BaseModel):
    hops: list[ReceivedHopOut] = Field(default_factory=list)
    chronological_hops: list[ReceivedHopOut] = Field(default_factory=list)
    total_hops: int = 0
    public_ips: list[str] = Field(default_factory=list)
    private_ips: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    earliest_timestamp: str | None = None
    latest_timestamp: str | None = None


def _build_headers_dict(email_record: Email) -> dict[str, str | list[str]]:
    """Convert stored EmailHeader rows to a dict."""
    headers: dict[str, str | list[str]] = {}
    for h in email_record.headers:
        key = h.name.lower()
        if key in headers:
            existing = headers[key]
            if isinstance(existing, list):
                existing.append(h.value)
            else:
                headers[key] = [existing, h.value]
        else:
            headers[key] = h.value
    return headers


def _run_received_analysis(email_record: Email) -> ReceivedChainAnalysis:
    """Parse and analyze Received headers."""
    headers = _build_headers_dict(email_record)
    return parse_received_headers(headers)


@router.post("/{email_id}/received", response_model=ReceivedChainOut)
def analyze_received(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Analyze Received headers and reconstruct the relay path."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    analysis = _run_received_analysis(email_record)

    return ReceivedChainOut(
        hops=[ReceivedHopOut(**h.to_dict()) for h in analysis.hops],
        chronological_hops=[ReceivedHopOut(**h.to_dict()) for h in analysis.chronological_hops],
        total_hops=analysis.total_hops,
        public_ips=analysis.public_ips,
        private_ips=analysis.private_ips,
        anomalies=analysis.anomalies,
        earliest_timestamp=analysis.earliest_timestamp.isoformat() if analysis.earliest_timestamp else None,
        latest_timestamp=analysis.latest_timestamp.isoformat() if analysis.latest_timestamp else None,
    )


@router.get("/{email_id}/received", response_model=ReceivedChainOut)
def get_received(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Retrieve Received header analysis (runs on-the-fly)."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    analysis = _run_received_analysis(email_record)

    return ReceivedChainOut(
        hops=[ReceivedHopOut(**h.to_dict()) for h in analysis.hops],
        chronological_hops=[ReceivedHopOut(**h.to_dict()) for h in analysis.chronological_hops],
        total_hops=analysis.total_hops,
        public_ips=analysis.public_ips,
        private_ips=analysis.private_ips,
        anomalies=analysis.anomalies,
        earliest_timestamp=analysis.earliest_timestamp.isoformat() if analysis.earliest_timestamp else None,
        latest_timestamp=analysis.latest_timestamp.isoformat() if analysis.latest_timestamp else None,
    )
