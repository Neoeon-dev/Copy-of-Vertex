"""ML classification endpoint.

POST /api/emails/{id}/classify — run ML threat classification
GET  /api/emails/{id}/classify  — retrieve classification results
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..ml.classifier import ClassificationResult, get_classifier
from ..models import Email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["ml"])


# ── Response schemas ─────────────────────────────────────────────────


class MLClassificationOut(BaseModel):
    email_id: int
    label: str
    confidence: float
    probabilities: dict[str, float] = Field(default_factory=dict)
    signals: dict[str, float] = Field(default_factory=dict)
    signal_details: dict[str, str] = Field(default_factory=dict)
    risk_score: float = 0.0


def _run_classification(email_record: Email) -> ClassificationResult:
    """Run ML classification on an email."""
    classifier = get_classifier()

    # Get auth results if available (simplified — just check subject/sender for now)
    return classifier.classify(
        subject=email_record.subject,
        sender=email_record.sender,
        sender_name=email_record.sender_name,
        body_text=email_record.body_text,
        body_html=email_record.body_html,
    )


@router.post("/{email_id}/classify", response_model=MLClassificationOut)
def classify_email(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Run ML threat classification on an email."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    try:
        result = _run_classification(email_record)
    except Exception as e:
        logger.exception("ML classification failed for email %d", email_id)
        raise HTTPException(status_code=500, detail=f"Classification failed: {type(e).__name__}: {e}")

    return MLClassificationOut(
        email_id=email_id,
        label=result.label,
        confidence=result.confidence,
        probabilities=result.probabilities,
        signals=result.signals,
        signal_details=result.signal_details,
        risk_score=result.risk_score,
    )


@router.get("/{email_id}/classify", response_model=MLClassificationOut)
def get_classification(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Retrieve ML classification results."""
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    result = _run_classification(email_record)

    return MLClassificationOut(
        email_id=email_id,
        label=result.label,
        confidence=result.confidence,
        probabilities=result.probabilities,
        signals=result.signals,
        signal_details=result.signal_details,
        risk_score=result.risk_score,
    )
