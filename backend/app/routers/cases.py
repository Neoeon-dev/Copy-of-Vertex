"""Case management and audit log endpoints.

POST   /api/cases              — create a case
GET    /api/cases              — list cases
GET    /api/cases/{id}         — get case detail
PUT    /api/cases/{id}         — update case
POST   /api/cases/{id}/emails  — assign email to case
GET    /api/cases/{id}/emails  — list emails in case
GET    /api/audit              — list audit log entries
POST   /api/audit/verify       — verify audit log integrity
GET    /api/evidence/verify/{email_id} — verify evidence chain
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.evidence import (
    add_audit_entry,
    add_evidence_entry,
    verify_audit_log_integrity,
    verify_chain_integrity,
)
from ..models import AuditLog, Case, Email

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cases"])


# ── Case schemas ─────────────────────────────────────────────────────


class CaseCreate(BaseModel):
    title: str
    description: str | None = None


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None


class CaseOut(BaseModel):
    id: int
    title: str
    description: str | None = None
    created_at: str
    email_count: int = 0


class AuditLogOut(BaseModel):
    id: int
    timestamp: str
    action: str
    entity_type: str
    entity_id: int | None = None
    actor: str
    details: str | None = None
    entry_hash: str


# ── Case endpoints ───────────────────────────────────────────────────


@router.post("/api/cases", response_model=CaseOut, status_code=201)
def create_case(
    data: CaseCreate,
    db: Annotated[Session, Depends(get_db)],
):
    case = Case(title=data.title, description=data.description)
    db.add(case)
    db.flush()

    add_audit_entry(db, "case.created", "case", case.id, details=f"Title: {data.title}")
    db.commit()
    db.refresh(case)

    return CaseOut(
        id=case.id,
        title=case.title,
        description=case.description,
        created_at=case.created_at.isoformat(),
        email_count=0,
    )


@router.get("/api/cases", response_model=list[CaseOut])
def list_cases(db: Annotated[Session, Depends(get_db)]):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    result = []
    for c in cases:
        email_count = db.query(Email).filter(Email.case_id == c.id).count()
        result.append(CaseOut(
            id=c.id,
            title=c.title,
            description=c.description,
            created_at=c.created_at.isoformat(),
            email_count=email_count,
        ))
    return result


@router.get("/api/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: int, db: Annotated[Session, Depends(get_db)]):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    email_count = db.query(Email).filter(Email.case_id == case.id).count()
    return CaseOut(
        id=case.id,
        title=case.title,
        description=case.description,
        created_at=case.created_at.isoformat(),
        email_count=email_count,
    )


@router.put("/api/cases/{case_id}", response_model=CaseOut)
def update_case(
    case_id: int,
    data: CaseUpdate,
    db: Annotated[Session, Depends(get_db)],
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if data.title is not None:
        case.title = data.title
    if data.description is not None:
        case.description = data.description

    add_audit_entry(db, "case.updated", "case", case_id, details=f"Updated: {data.model_dump(exclude_none=True)}")
    db.commit()
    db.refresh(case)

    email_count = db.query(Email).filter(Email.case_id == case.id).count()
    return CaseOut(
        id=case.id,
        title=case.title,
        description=case.description,
        created_at=case.created_at.isoformat(),
        email_count=email_count,
    )


@router.post("/api/cases/{case_id}/emails/{email_id}")
def assign_email_to_case(
    case_id: int,
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    email.case_id = case_id
    add_audit_entry(db, "email.assigned_to_case", "email", email_id, details=f"Case: {case_id}")
    add_evidence_entry(db, email_id, email.sha256, "assigned_to_case", f"Case: {case.title}")
    db.commit()

    return {"status": "ok", "email_id": email_id, "case_id": case_id}


@router.get("/api/cases/{case_id}/emails")
def list_case_emails(
    case_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    emails = db.query(Email).filter(Email.case_id == case_id).order_by(Email.created_at.desc()).all()
    return [
        {
            "id": e.id,
            "subject": e.subject,
            "sender": e.sender,
            "sha256": e.sha256,
            "created_at": e.created_at.isoformat(),
        }
        for e in emails
    ]


# ── Audit log endpoints ──────────────────────────────────────────────


@router.get("/api/audit", response_model=list[AuditLogOut])
def list_audit_log(
    db: Annotated[Session, Depends(get_db)],
    skip: int = 0,
    limit: int = 100,
):
    entries = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        AuditLogOut(
            id=e.id,
            timestamp=e.timestamp.isoformat(),
            action=e.action,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            actor=e.actor,
            details=e.details,
            entry_hash=e.entry_hash,
        )
        for e in entries
    ]


@router.post("/api/audit/verify")
def verify_audit(db: Annotated[Session, Depends(get_db)]):
    is_valid, errors = verify_audit_log_integrity(db)
    entry_count = db.query(AuditLog).count()
    return {
        "valid": is_valid,
        "entry_count": entry_count,
        "errors": errors,
    }


@router.get("/api/evidence/verify/{email_id}")
def verify_evidence(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    is_valid, errors = verify_chain_integrity(db, email_id)
    from ..models import EvidenceChain
    entry_count = db.query(EvidenceChain).filter(EvidenceChain.email_id == email_id).count()
    return {
        "email_id": email_id,
        "evidence_id": email.sha256,
        "valid": is_valid,
        "entry_count": entry_count,
        "errors": errors,
    }
