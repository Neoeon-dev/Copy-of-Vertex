"""Trained forensic model classification endpoint.

POST /api/emails/{id}/classify — run the trained forensic model
GET  /api/emails/{id}/classify  — retrieve the current model result
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..ml.models.forensic_service import get_forensic_service
from ..models import Email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/emails", tags=["ml"])


class MLClassificationOut(BaseModel):
    email_id: int
    label: str
    confidence: float
    probabilities: dict[str, float] = Field(default_factory=dict)
    risk_score: float = 0.0
    model_version: str = "unknown"
    model_architecture: str = "LightGBM-Tabular"
    feature_count: int = 0
    calibration_method: str = "unknown"
    latency_ms: float = 0.0
    top_features: list[dict[str, Any]] = Field(default_factory=list)
    # Kept for backwards compatibility with the original frontend contract.
    signals: dict[str, float] = Field(default_factory=dict)
    signal_details: dict[str, str] = Field(default_factory=dict)


def _run_classification(email_record: Email):
    service = get_forensic_service()

    from email.message import EmailMessage
    from email.policy import default

    # Prefer the pristine uploaded payload when available. It is the exact
    # evidence bytes and avoids changing MIME semantics during reconstruction.
    if email_record.raw_payload is not None and email_record.raw_payload.raw_bytes:
        return service.predict_raw_email(email_record.raw_payload.raw_bytes)

    message = EmailMessage(policy=default)

    # Structural MIME headers describe the original wire representation. Do not
    # copy them onto a newly constructed EmailMessage because set_content() /
    # add_alternative() must be allowed to choose the new MIME structure.
    structural_headers = {
        "content-type",
        "content-transfer-encoding",
        "mime-version",
        "content-disposition",
        "content-id",
    }
    for header in email_record.headers:
        if header.name.lower() in structural_headers:
            continue
        message[header.name] = header.value

    # Rebuild a MIME representation from the stored evidence so the forensic
    # extractor still sees headers, body, and attachment metadata/content.
    if email_record.body_text and email_record.body_html:
        message.set_content(email_record.body_text)
        message.add_alternative(email_record.body_html, subtype="html")
    elif email_record.body_text:
        message.set_content(email_record.body_text)
    elif email_record.body_html:
        message.set_content("This message contains an HTML body.")
        message.add_alternative(email_record.body_html, subtype="html")
    else:
        message.set_content("")

    for attachment in email_record.attachments:
        content = attachment.content or b""
        content_type = attachment.content_type or "application/octet-stream"
        maintype, _, subtype = content_type.partition("/")
        message.add_attachment(
            content,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=attachment.filename or "attachment",
        )

    return service.predict_raw_email(message.as_bytes())


def _to_response(email_id: int, prediction) -> MLClassificationOut:
    metadata = prediction.to_dict()
    return MLClassificationOut(
        email_id=email_id,
        label=metadata["predicted_label"],
        confidence=metadata["confidence"],
        probabilities=metadata["probabilities"],
        risk_score=metadata["risk_score"],
        model_version=metadata["model_version"],
        model_architecture="LightGBM-Tabular",
        feature_count=metadata["features_used_count"],
        calibration_method=metadata.get("calibration_method", "unknown"),
        latency_ms=metadata.get("latency_ms", 0.0),
        top_features=metadata.get("top_contributing_features", []),
        signals={item.get("feature", ""): float(item.get("value", 0.0)) for item in metadata.get("top_contributing_features", []) if item.get("feature")},
        signal_details={},
    )


@router.post("/{email_id}/classify", response_model=MLClassificationOut)
def classify_email(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    try:
        return _to_response(email_id, _run_classification(email_record))
    except Exception as e:
        logger.exception("Forensic model classification failed for email %d", email_id)
        raise HTTPException(status_code=500, detail=f"Forensic model failed: {type(e).__name__}: {e}")


@router.get("/{email_id}/classify", response_model=MLClassificationOut)
def get_classification(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    email_record = db.query(Email).filter(Email.id == email_id).first()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    try:
        return _to_response(email_id, _run_classification(email_record))
    except Exception as e:
        logger.exception("Forensic model retrieval failed for email %d", email_id)
        raise HTTPException(status_code=500, detail=f"Forensic model failed: {type(e).__name__}: {e}")
