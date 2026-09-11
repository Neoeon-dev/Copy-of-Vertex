"""Email authentication analysis endpoint.

GET /api/emails/{email_id}/authentication — run SPF/DKIM/DMARC analysis
POST /api/emails/{email_id}/authentication — trigger and store auth analysis
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.dkim_analyzer import analyze_dkim
from ..forensics.dmarc_analyzer import analyze_dmarc
from ..forensics.spf_analyzer import analyze_spf
from ..models import Email, EmailAuthenticationResult
from ..schemas.email import AuthResultOut, AuthenticationSummary
from ..utils import get_headers_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["authentication"])





def _get_raw_email_bytes(email_record: Email) -> bytes | None:
    """Reconstruct raw email bytes from stored headers + body for DKIM verification.

    This is a best-effort reconstruction; the original raw bytes are the
    evidence hash. We need raw bytes for dkimpy verification.
    """
    lines: list[str] = []
    for h in email_record.headers:
        lines.append(f"{h.name}: {h.value}")
    lines.append("")  # blank line separating headers from body
    if email_record.body_text:
        lines.append(email_record.body_text)
    return "\r\n".join(lines).encode("utf-8", errors="replace")


def _persist_auth_results(
    db: Session,
    email_id: int,
    results: list[EmailAuthenticationResult],
) -> None:
    """Store authentication results in the database."""
    for result in results:
        db.add(result)
    db.commit()


def _run_authentication_analysis(
    email_record: Email,
) -> AuthenticationSummary:
    """Run SPF, DKIM, and DMARC analysis on an email."""
    headers = get_headers_dict(email_record.headers)
    raw_bytes = _get_raw_email_bytes(email_record)
    from_domain = email_record.sender

    # ── SPF Analysis ──
    spf = analyze_spf(
        headers=headers,
        email_sender_domain=from_domain,
    )

    # ── DKIM Analysis ──
    dkim_results = analyze_dkim(
        headers=headers,
        raw_email_bytes=raw_bytes,
        email_sender_domain=from_domain,
    )
    # Use the first DKIM result for DMARC evaluation
    dkim_best = dkim_results[0] if dkim_results else None

    # ── DMARC Analysis ──
    spf_envelope_domain = spf.domain if spf.domain != from_domain else None
    dmarc = analyze_dmarc(
        email_sender_domain=from_domain,
        spf_result=spf.result,
        spf_envelope_domain=spf_envelope_domain,
        dkim_result=dkim_best.result if dkim_best else None,
        dkim_domain=dkim_best.domain if dkim_best else None,
    )

    # Build the summary
    all_results: list[AuthResultOut] = []

    # SPF
    spf_out = AuthResultOut(
        mechanism="SPF",
        result=spf.result,
        domain=spf.domain,
        aligned=None,
        source=spf.source,
        details=spf.details or spf.error,
        checked_at=email_record.created_at,
    )
    all_results.append(spf_out)

    # DKIM (all signatures)
    for dr in dkim_results:
        dkim_out = AuthResultOut(
            mechanism="DKIM",
            result=dr.result,
            domain=dr.domain,
            selector=dr.selector,
            aligned=None,
            source=dr.source,
            details=dr.details or dr.error,
            checked_at=email_record.created_at,
        )
        all_results.append(dkim_out)

    # DMARC
    dmarc_out = AuthResultOut(
        mechanism="DMARC",
        result=dmarc.result,
        domain=dmarc.domain,
        aligned=None,
        source=dmarc.source,
        details=dmarc.details or dmarc.error,
        checked_at=email_record.created_at,
    )
    all_results.append(dmarc_out)

    # Use the first dkim_out from all_results for the summary
    dkim_first = next((r for r in all_results if r.mechanism == "DKIM"), None)

    return AuthenticationSummary(
        spf=spf_out,
        dkim=dkim_first,
        dmarc=dmarc_out,
        all_results=all_results,
    )


@router.post("/{email_id}/authentication", response_model=AuthenticationSummary)
def run_authentication(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Run and persist SPF/DKIM/DMARC authentication analysis for an email."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    summary = _run_authentication_analysis(email_record)

    # Persist results to DB
    db_results: list[EmailAuthenticationResult] = []
    for ar in summary.all_results:
        db_results.append(EmailAuthenticationResult(
            email_id=email_id,
            mechanism=ar.mechanism,
            result=ar.result,
            domain=ar.domain,
            selector=ar.selector if hasattr(ar, "selector") else None,
            aligned=ar.aligned,
            source=ar.source,
            details=ar.details,
        ))
    _persist_auth_results(db, email_id, db_results)

    logger.info(
        "Authentication analysis complete for email %d: SPF=%s DKIM=%s DMARC=%s",
        email_id,
        summary.spf.result if summary.spf else "N/A",
        summary.dkim.result if summary.dkim else "N/A",
        summary.dmarc.result if summary.dmarc else "N/A",
    )

    return summary


@router.get("/{email_id}/authentication", response_model=AuthenticationSummary)
def get_authentication(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Retrieve previously computed authentication results."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    # Check if we already have stored results
    stored = (
        db.query(EmailAuthenticationResult)
        .filter(EmailAuthenticationResult.email_id == email_id)
        .all()
    )

    if stored:
        all_results = [AuthResultOut.model_validate(r) for r in stored]
        spf = next((r for r in all_results if r.mechanism == "SPF"), None)
        dkim = next((r for r in all_results if r.mechanism == "DKIM"), None)
        dmarc = next((r for r in all_results if r.mechanism == "DMARC"), None)
        return AuthenticationSummary(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            all_results=all_results,
        )

    # No stored results — run analysis now
    summary = _run_authentication_analysis(email_record)

    # Persist
    db_results = []
    for ar in summary.all_results:
        db_results.append(EmailAuthenticationResult(
            email_id=email_id,
            mechanism=ar.mechanism,
            result=ar.result,
            domain=ar.domain,
            aligned=ar.aligned,
            source=ar.source,
            details=ar.details,
        ))
    _persist_auth_results(db, email_id, db_results)

    return summary
