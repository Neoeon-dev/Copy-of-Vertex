"""Evidence hash chain for tamper-evident audit trail.

Implements an append-only hash chain where each entry includes:
- SHA-256 of the raw evidence (email bytes)
- SHA-256 of the action data
- SHA-256 of the previous chain entry
- Combined chain hash = SHA256(content_hash + previous_hash)

This ensures that modifying any record in the chain breaks the integrity.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import AuditLog, EvidenceChain

logger = logging.getLogger(__name__)


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_chain_hash(content_hash: str, previous_hash: str | None) -> str:
    """Compute the chain integrity hash."""
    combined = f"{content_hash}:{previous_hash or 'GENESIS'}"
    return _sha256(combined)


def get_last_chain_hash(db: Session, email_id: int | None = None) -> str | None:
    """Get the most recent chain hash for an email or globally."""
    query = db.query(EvidenceChain).order_by(EvidenceChain.id.desc())
    if email_id is not None:
        query = query.filter(EvidenceChain.email_id == email_id)
    last = query.first()
    return last.chain_hash if last else None


def add_evidence_entry(
    db: Session,
    email_id: int,
    evidence_id: str,
    action: str,
    details: str | None = None,
) -> EvidenceChain:
    """Add an entry to the evidence hash chain.

    Args:
        db: Database session
        email_id: The email this evidence relates to
        evidence_id: SHA-256 of the raw email bytes
        action: The action taken (uploaded, analyzed, exported, etc.)
        details: Optional human-readable details

    Returns:
        The created EvidenceChain entry
    """
    previous_hash = get_last_chain_hash(db, email_id)

    # Compute content hash from action + details
    content_data = json.dumps({
        "email_id": email_id,
        "evidence_id": evidence_id,
        "action": action,
        "details": details,
    }, sort_keys=True)
    content_hash = _sha256(content_data)

    # Compute chain hash
    chain_hash = compute_chain_hash(content_hash, previous_hash)

    entry = EvidenceChain(
        email_id=email_id,
        evidence_id=evidence_id,
        action=action,
        content_hash=content_hash,
        previous_hash=previous_hash,
        chain_hash=chain_hash,
        details=details,
    )
    db.add(entry)
    db.flush()

    logger.info(
        "Evidence chain entry added: email=%d action=%s chain=%s",
        email_id, action, chain_hash[:12],
    )
    return entry


def add_audit_entry(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: int | None = None,
    actor: str = "system",
    details: str | None = None,
) -> AuditLog:
    """Add an entry to the append-only audit log.

    Args:
        db: Database session
        action: The action taken
        entity_type: Type of entity (email, case, analysis)
        entity_id: ID of the entity
        actor: Who performed the action
        details: Optional human-readable details

    Returns:
        The created AuditLog entry
    """
    # Get previous hash
    last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous_hash = last_entry.entry_hash if last_entry else None

    # Compute entry hash
    entry_data = json.dumps({
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "details": details,
        "previous_hash": previous_hash,
    }, sort_keys=True)
    entry_hash = _sha256(entry_data)

    log_entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        details=details,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )
    db.add(log_entry)
    db.flush()

    return log_entry


def verify_chain_integrity(
    db: Session,
    email_id: int | None = None,
) -> tuple[bool, list[str]]:
    """Verify the integrity of the evidence hash chain.

    Returns:
        (is_valid, list_of_errors)
    """
    query = db.query(EvidenceChain).order_by(EvidenceChain.id.asc())
    if email_id is not None:
        query = query.filter(EvidenceChain.email_id == email_id)

    entries = query.all()
    errors: list[str] = []
    prev_hash: str | None = None

    for entry in entries:
        # Verify previous hash link
        if entry.previous_hash != prev_hash:
            errors.append(
                f"Entry {entry.id}: previous_hash mismatch "
                f"(expected={prev_hash}, got={entry.previous_hash})"
            )

        # Verify chain hash
        expected_chain = compute_chain_hash(entry.content_hash, entry.previous_hash)
        if entry.chain_hash != expected_chain:
            errors.append(
                f"Entry {entry.id}: chain_hash mismatch "
                f"(expected={expected_chain[:12]}, got={entry.chain_hash[:12]})"
            )

        prev_hash = entry.chain_hash

    return len(errors) == 0, errors


def verify_audit_log_integrity(db: Session) -> tuple[bool, list[str]]:
    """Verify the integrity of the audit log chain."""
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    errors: list[str] = []
    prev_hash: str | None = None

    for entry in entries:
        if entry.previous_hash != prev_hash:
            errors.append(
                f"Audit entry {entry.id}: previous_hash mismatch"
            )
        prev_hash = entry.entry_hash

    return len(errors) == 0, errors
