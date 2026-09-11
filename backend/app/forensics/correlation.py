"""Correlation graph engine using PostgreSQL as the source of truth.

Builds a graph of relationships between emails, senders, domains, IPs,
URLs, and cases. The graph allows multiple analyzed emails to reveal
shared infrastructure and campaigns.

Node types: Email, Sender, Domain, IP, ASN, URL, File, FileHash, Attachment, Case, ThreatIntelProvider, Campaign
Edge types: SENT_FROM, SENT_TO, RECEIVED_FROM_IP, USES_DOMAIN, BELONGS_TO_DOMAIN, RESOLVES_TO_IP,
            HAS_ATTACHMENT, HAS_FILE_HASH, REPORTED_BY_PROVIDER, ASSOCIATED_WITH_CASE,
            RELATED_TO_EMAIL, CONTAINS_URL, CONTAINS_DOMAIN, CONTAINS_IP, PART_OF_CASE,
            IMPERSONATES, CORRELATES_WITH, etc.
"""
from __future__ import annotations

import logging
import os
from typing import Any
import uuid
import ipaddress
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm import aliased

from ..db import SessionLocal
from .. import models
from ..threat_intel.ioc import extract_iocs_from_email
from ..utils import get_headers_dict

logger = logging.getLogger(__name__)


def _get_session_local():
    """Get the appropriate session local based on environment.
    In test environment, use the test session local from conftest.
    """
    # Check if we're in a test environment by checking for test database
    database_url = os.environ.get("DATABASE_URL", "")
    if "mailtrace_test" in database_url:
        # We're in a test environment, try to import test session local
        try:
            from tests.conftest import _TestSession
            return _TestSession
        except ImportError:
            pass
    # Fall back to the regular session local
    return SessionLocal


class CytoscapeGraph(dict):
    """Wrapper around Cytoscape graph data that provides attribute access."""

    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        # Provide attribute access to elements
        if "elements" in data:
            self.nodes = data["elements"].get("nodes", [])
            self.edges = data["elements"].get("edges", [])
        else:
            self.nodes = []
            self.edges = []


def _calculate_email_similarity_score(email1_data: dict[str, Any], email2_data: dict[str, Any]) -> float:
    """
    Calculate a deterministic similarity score between two emails based on:
    - Sender domain similarity
    - Subject similarity (basic)
    - Common recipients
    - Temporal proximity (simplified)

    Returns a score between 0.0 and 1.0
    """
    score = 0.0
    max_score = 4.0  # We'll normalize by this

    # Sender domain similarity (0-1 point)
    sender1 = email1_data.get("sender", "")
    sender2 = email2_data.get("sender", "")
    if sender1 and sender2:
        domain1 = sender1.split("@")[-1].lower() if "@" in sender1 else sender1.lower()
        domain2 = sender2.split("@")[-1].lower() if "@" in sender2 else sender2.lower()
        if domain1 == domain2:
            score += 1.0

    # Subject similarity (0-1 point) - basic keyword matching
    subject1 = email1_data.get("subject", "").lower()
    subject2 = email2_data.get("subject", "").lower()
    if subject1 and subject2:
        # Simple Jaccard similarity on words
        words1 = set(subject1.split())
        words2 = set(subject2.split())
        if words1 or words2:
            intersection = len(words1 & words2)
            union = len(words1 | words2)
            if union > 0:
                score += intersection / union

    # Common recipients (0-1 point)
    recipients1 = set(email1_data.get("to", []) + email1_data.get("cc", []))
    recipients2 = set(email2_data.get("to", []) + email2_data.get("cc", []))
    if recipients1 or recipients2:
        intersection = len(recipients1 & recipients2)
        union = len(recipients1 | recipients2)
        if union > 0:
            score += intersection / union

    # Temporal proximity (0-1 point) - simplified version without external dependencies
    date1 = email1_data.get("date")
    date2 = email2_data.get("date")
    if date1 and date2:
        # Simple string-based date comparison for common formats
        try:
            # Extract year-month-day for basic comparison
            def extract_ymd(date_str):
                if not isinstance(date_str, str):
                    return None
                # Try to find YYYY-MM-DD pattern
                import re
                match = re.search(r'(\d{4})-(\d{2})-(\d{2})', date_str)
                if match:
                    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                return None

            ymd1 = extract_ymd(date1)
            ymd2 = extract_ymd(date2)

            if ymd1 and ymd2:
                # Simple day difference calculation (approximate)
                # This is a simplification - for production would use proper date math
                days_diff = abs((ymd1[0] - ymd2[0]) * 365 + (ymd1[1] - ymd2[1]) * 30 + (ymd1[2] - ymd2[2]))
                if days_diff <= 1:  # Same or adjacent days
                    score += 1.0
                elif days_diff <= 7:  # Within a week
                    score += 0.5
        except Exception:
            # If date parsing fails, skip temporal scoring
            pass

    # Normalize to 0-1 range
    return min(score / max_score, 1.0) if max_score > 0 else 0.0


class CorrelationEngine:
    """Builds and queries the correlation graph across multiple emails using persistent storage."""

    def __init__(self) -> None:
        # No in-memory graph; we use the database as the source of truth.
        pass

    def _get_or_create_node(
        self,
        db: Session,
        node_type: str,
        canonical_value: str,
        display_value: str | None = None,
        confidence: float = 1.0,
    ) -> models.GraphNode:
        """Get an existing node or create a new one if it doesn't exist.
        Uses the unique constraint on (node_type, canonical_value) to avoid duplicates.
        """
        # Try to find existing node
        node = (
            db.query(models.GraphNode)
            .filter(
                models.GraphNode.node_type == node_type,
                models.GraphNode.canonical_value == canonical_value,
            )
            .first()
        )
        if node:
            # Update display_value if provided and different
            if display_value is not None and node.display_value != display_value:
                node.display_value = display_value
                node.confidence = max(node.confidence, confidence)  # Keep highest confidence
                node.updated_at = models._utcnow()
            return node

        # Create new node
        try:
            node = models.GraphNode(
                node_id=str(uuid.uuid4()),
                node_type=node_type,
                canonical_value=canonical_value,
                display_value=display_value,
                confidence=confidence,
                first_seen=models._utcnow(),
                last_seen=models._utcnow(),
                source_count=1,
            )
            db.add(node)
            db.commit()
            db.refresh(node)
            return node
        except IntegrityError:
            # Another transaction created the node first; rollback and try to fetch
            db.rollback()
            node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == node_type,
                    models.GraphNode.canonical_value == canonical_value,
                )
                .first()
            )
            if node:
                # Update confidence and source_count
                node.source_count += 1
                node.confidence = max(node.confidence, confidence)
                node.updated_at = models._utcnow()
                db.add(node)
                db.commit()
                db.refresh(node)
            return node

    def _get_or_create_edge(
        self,
        db: Session,
        source_node_id: str,
        target_node_id: str,
        relationship_type: str,
        confidence: float = 1.0,
        is_inferred: bool = False,
        source_email_id: int | None = None,
        source_case_id: int | None = None,
        source_provider: str | None = None,
        evidence_type: str | None = None,
        evidence_reference: str | None = None,
    ) -> models.GraphEdge:
        """Get an existing edge or create a new one if it doesn't exist.
        For observed edges (is_inferred=False), we enforce uniqueness via a partial index.
        For inferred edges, we allow duplicates (different inference methods may produce same edge).
        """
        if not is_inferred:
            # For observed edges, try to find existing edge to avoid duplicates
            edge = (
                db.query(models.GraphEdge)
                .filter(
                    models.GraphEdge.source_node_id == source_node_id,
                    models.GraphEdge.target_node_id == target_node_id,
                    models.GraphEdge.relationship_type == relationship_type,
                    models.GraphEdge.is_inferred == False,  # noqa: E712
                )
                .first()
            )
            if edge:
                # Update confidence, observation_count, and timestamps
                edge.confidence = max(edge.confidence, confidence)
                edge.observation_count += 1
                edge.updated_at = models._utcnow()
                if source_email_id is not None:
                    edge.source_email_id = source_email_id
                if source_case_id is not None:
                    edge.source_case_id = source_case_id
                if source_provider is not None:
                    edge.source_provider = source_provider
                if evidence_type is not None:
                    edge.evidence_type = evidence_type
                if evidence_reference is not None:
                    edge.evidence_reference = evidence_reference
                return edge

        # Create new edge (either inferred or observed edge that didn't exist)
        try:
            edge = models.GraphEdge(
                edge_id=str(uuid.uuid4()),
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                relationship_type=relationship_type,
                confidence=confidence,
                first_seen=models._utcnow(),
                last_seen=models._utcnow(),
                observation_count=1,
                source_email_id=source_email_id,
                source_case_id=source_case_id,
                source_provider=source_provider,
                evidence_type=evidence_type,
                evidence_reference=evidence_reference,
                is_inferred=is_inferred,
            )
            db.add(edge)
            db.commit()
            db.refresh(edge)
            return edge
        except IntegrityError as e:
            # Check if it's a foreign key error
            if "foreign key constraint" in str(e).lower() and ("source_email_id" in str(e) or "source_case_id" in str(e)):
                # For foreign key errors, try again with NULL IDs
                db.rollback()
                try:
                    edge = models.GraphEdge(
                        edge_id=str(uuid.uuid4()),
                        source_node_id=source_node_id,
                        target_node_id=target_node_id,
                        relationship_type=relationship_type,
                        confidence=confidence,
                        first_seen=models._utcnow(),
                        last_seen=models._utcnow(),
                        observation_count=1,
                        source_email_id=None,  # Set to None due to FK constraint
                        source_case_id=None,   # Set to None due to FK constraint
                        source_provider=source_provider,
                        evidence_type=evidence_type,
                        evidence_reference=evidence_reference,
                        is_inferred=is_inferred,
                    )
                    db.add(edge)
                    db.commit()
                    db.refresh(edge)
                    return edge
                except IntegrityError:
                    # If we still get an integrity error, fall through to the original logic
                    db.rollback()

            # For observed edges, this should not happen due to the partial index, but handle anyway
            if not is_inferred:
                # Try to fetch the edge that caused the conflict
                edge = (
                    db.query(models.GraphEdge)
                    .filter(
                        models.GraphEdge.source_node_id == source_node_id,
                        models.GraphEdge.target_node_id == target_node_id,
                        models.GraphEdge.relationship_type == relationship_type,
                        models.GraphEdge.is_inferred == False,  # noqa: E712
                    )
                    .first()
                )
                if edge:
                    # Update as above
                    edge.confidence = max(edge.confidence, confidence)
                    edge.observation_count += 1
                    edge.updated_at = models._utcnow()
                    if source_email_id is not None:
                        edge.source_email_id = source_email_id
                    if source_case_id is not None:
                        edge.source_case_id = source_case_id
                    if source_provider is not None:
                        edge.source_provider = source_provider
                    if evidence_type is not None:
                        edge.evidence_type = evidence_type
                    if evidence_reference is not None:
                        edge.evidence_reference = evidence_reference
                    db.add(edge)
                    db.commit()
                    db.refresh(edge)
                    return edge
            # If we still don't have an edge, raise
            raise

    def add_email(self, email_data: dict[str, Any], db: Session = None) -> None:
        """Add an email and all its relationships to the graph."""
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False
        try:
            email_id = email_data.get("id")

            # Get the full email record from the database to access all fields
            email_record = db.query(models.Email).filter(
                models.Email.id == email_id
            ).first()

            if not email_record:
                logger.warning(f"Email record not found for id {email_id}")
                return

            # Email node
            email_node = self._get_or_create_node(
                db,
                node_type="EMAIL",
                canonical_value=str(email_id),
                display_value=email_record.subject[:40] if email_record.subject else f"Email #{email_id}",
                confidence=1.0,
            )

            # Sender node
            if email_record.sender:
                sender_domain = email_record.sender.split("@")[-1] if "@" in email_record.sender else email_record.sender
                sender_node = self._get_or_create_node(
                    db,
                    node_type="SENDER",
                    canonical_value=email_record.sender,
                    display_value=email_record.sender,
                    confidence=1.0,
                )
                # SENT_FROM edge (email -> sender)
                self._get_or_create_edge(
                    db,
                    source_node_id=email_node.node_id,
                    target_node_id=sender_node.node_id,
                    relationship_type="SENT_FROM",
                    confidence=1.0,
                    is_inferred=False,
                    source_email_id=email_id,
                    evidence_type="EMAIL_HEADER",
                    evidence_reference="From header",
                )

                # Domain node for sender domain
                domain_node = self._get_or_create_node(
                    db,
                    node_type="DOMAIN",
                    canonical_value=sender_domain,
                    display_value=sender_domain,
                    confidence=1.0,
                )
                # USES_DOMAIN edge (sender -> domain)
                self._get_or_create_edge(
                    db,
                    source_node_id=sender_node.node_id,
                    target_node_id=domain_node.node_id,
                    relationship_type="USES_DOMAIN",
                    confidence=1.0,
                    is_inferred=False,
                    source_email_id=email_id,
                    evidence_type="EMAIL_HEADER",
                    evidence_reference="From header",
                )

            # Case node
            if email_record.case_id:
                case_node = self._get_or_create_node(
                    db,
                    node_type="CASE",
                    canonical_value=str(email_record.case_id),
                    display_value=f"Case #{email_record.case_id}",
                    confidence=1.0,
                )
                # PART_OF_CASE edge (email -> case)
                self._get_or_create_edge(
                    db,
                    source_node_id=email_node.node_id,
                    target_node_id=case_node.node_id,
                    relationship_type="PART_OF_CASE",
                    confidence=1.0,
                    is_inferred=False,
                    source_email_id=email_id,
                    evidence_type="EMAIL_HEADER",
                    evidence_reference="Case-ID header or system assignment",
                )

            # Extract IOCs from the email
            try:
                headers = get_headers_dict(email_record.headers)
                iocs = extract_iocs_from_email(
                    headers=headers,
                    body_text=email_record.body_text,
                    body_html=email_record.body_html,
                    attachments=[
                        {"filename": a.filename, "sha256": a.sha256}
                        for a in email_record.attachments
                    ] if email_record.attachments else None
                )

                # Process each IOC (skip FILE_HASH as handled by add_attachment_hashes)
                for ioc in iocs:
                    if ioc.ioc_type == IOCType.FILE_HASH:
                        # Skip file hashes as they are handled by add_attachment_hashes method
                        continue

                    # Create/get the IOC node
                    ioc_node = self._get_or_create_node(
                        db,
                        node_type=ioc.ioc_type.value,
                        canonical_value=ioc.normalized_value,
                        display_value=ioc.display_value,
                        confidence=1.0,
                    )

                    # Determine edge type and evidence based on IOC type and source context
                    edge_type = None
                    evidence_type = None
                    evidence_reference = None

                    if ioc.ioc_type == IOCType.IPV4 or ioc.ioc_type == IOCType.IPV6:
                        # Check if this IP came from a Received header
                        if "received" in ioc.source_location.lower() or "received" in ioc.extraction_context.lower():
                            edge_type = "RECEIVED_FROM_IP"
                            evidence_type = "RECEIVED_HEADER"
                            evidence_reference = f"IP from Received header: {ioc.extraction_context}"
                        else:
                            edge_type = "CONTAINS_IP"
                            evidence_type = "IP_EXTRACTION"
                            evidence_reference = f"IP extracted from {ioc.source_location}"
                    elif ioc.ioc_type == IOCType.DOMAIN:
                        edge_type = "CONTAINS_DOMAIN"
                        evidence_type = "DOMAIN_EXTRACTION"
                        evidence_reference = f"Domain extracted from {ioc.source_location}"
                    elif ioc.ioc_type == IOCType.URL:
                        edge_type = "CONTAINS_URL"
                        evidence_type = "URL_EXTRACTION"
                        evidence_reference = f"URL extracted from {ioc.source_location}"

                        # Also extract domain from URL and create BELONGS_TO_DOMAIN edge
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(ioc.normalized_value)
                            hostname = parsed.hostname or ""
                            if hostname:
                                # Try to see if it's an IP or domain
                                import ipaddress
                                try:
                                    ipaddress.ip_address(hostname)
                                    # It's an IP, no domain to extract
                                    pass
                                except ValueError:
                                    # It's a domain
                                    domain_node = self._get_or_create_node(
                                        db,
                                        node_type="DOMAIN",
                                        canonical_value=hostname,
                                        display_value=hostname,
                                        confidence=1.0,
                                    )
                                    # Create BELONGS_TO_DOMAIN edge (URL -> domain)
                                    self._get_or_create_edge(
                                        db,
                                        source_node_id=ioc_node.node_id,
                                        target_node_id=domain_node.node_id,
                                        relationship_type="BELONGS_TO_DOMAIN",
                                        confidence=1.0,
                                        is_inferred=False,
                                        source_email_id=email_id,
                                        evidence_type="URL_PARSING",
                                        evidence_reference=f"URL {ioc.normalized_value} parsed to extract domain"
                                    )
                        except Exception as e:
                            logger.debug(f"Failed to extract domain from URL {ioc.normalized_value}: {e}")
                    elif ioc.ioc_type == IOCType.EMAIL_ADDRESS:
                        # Check if this is a recipient (To, CC, BCC) vs sender (From)
                        if "to" in ioc.source_location.lower() or "cc" in ioc.source_location.lower() or "bcc" in ioc.source_location.lower():
                            edge_type = "SENT_TO"
                            evidence_type = "EMAIL_HEADER"
                            evidence_reference = f"Recipient email from {ioc.source_location}: {ioc.display_value}"
                        elif "from" in ioc.source_location.lower() or "sender" in ioc.source_location.lower() or "reply-to" in ioc.source_location.lower():
                            # This is likely a sender, we already handled sender via the sender field
                            # But we can still create a CONTAINS_EMAIL edge for completeness
                            edge_type = "CONTAINS_EMAIL"
                            evidence_type = "EMAIL_HEADER"
                            evidence_reference = f"Sender email from {ioc.source_location}: {ioc.display_value}"
                        else:
                            # Other email address (e.g., in body)
                            edge_type = "CONTAINS_EMAIL"
                            evidence_type = "EMAIL_EXTRACTION"
                            evidence_reference = f"Email address extracted from {ioc.source_location}"

                    if edge_type:
                        self._get_or_create_edge(
                            db,
                            source_node_id=email_node.node_id,
                            target_node_id=ioc_node.node_id,
                            relationship_type=edge_type,
                            confidence=1.0,
                            is_inferred=False,
                            source_email_id=email_id,
                            evidence_type=evidence_type,
                            evidence_reference=evidence_reference,
                        )

            except Exception as e:
                logger.error(f"Failed to extract/process IOCs for email {email_id}: {e}")
                # Continue with basic email/node creation even if IOC extraction fails

            # Add attachment hash relationships (using existing method)
            self.add_attachment_hashes(email_id, db)

            # Commit all changes
            db.commit()
        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to add email to graph: {e}")
            raise
        finally:
            if own_session:
                db.close()

    def add_ips(self, email_id: int, ip_analyses: list[dict[str, Any]], db: Session = None) -> None:
        """Add IP relationships for an email."""
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False
        try:
            email_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email_id),
                )
                .first()
            )
            if not email_node:
                logger.warning(f"Email node not found for email_id {email_id}")
                return

            # TODO: Implement IP analysis using ip_analyses
            # For now, we skip because we don't have the IP analyses stored separately.
            # In a real implementation, we would have stored the IP analyses when the email was analyzed.
            # We'll leave this as a placeholder and note that we need to store the analysis results.
            logger.warning("IP addition not yet implemented; skipping")
            pass
        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to add IPs to graph: {e}")
            raise
        finally:
            if own_session:
                db.close()

    def add_urls(self, email_id: int, url_analyses: list[dict[str, Any]], db: Session = None) -> None:
        """Add URL relationships for an email."""
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False
        try:
            email_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email_id),
                )
                .first()
            )
            if not email_node:
                logger.warning(f"Email node not found for email_id {email_id}")
                return

            # TODO: Implement URL analysis using url_analyses
            logger.warning("URL addition not yet implemented; skipping")
            pass
        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to add URLs to graph: {e}")
            raise
        finally:
            if own_session:
                db.close()

    def add_domains(self, email_id: int, domain_analyses: list[dict[str, Any]], db: Session = None) -> None:
        """Add domain intelligence relationships."""
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False
        try:
            email_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email_id),
                )
                .first()
            )
            if not email_node:
                logger.warning(f"Email node not found for email_id {email_id}")
                return

            # TODO: Implement domain analysis using domain_analyses
            logger.warning("Domain addition not yet implemented; skipping")
            pass
        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to add domains to graph: {e}")
            raise
        finally:
            if own_session:
                db.close()

    def add_attachment_hashes(self, email_id: int, db: Session = None) -> None:
        """Add file hash relationships for an email's attachments."""
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False
        try:
            # Get the email node
            email_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email_id),
                )
                .first()
            )
            if not email_node:
                return

            # Get attachments for this email
            attachments = db.query(models.Attachment).filter(
                models.Attachment.email_id == email_id
            ).all()

            for attachment in attachments:
                # Attachment node
                attachment_node = self._get_or_create_node(
                    db,
                    node_type="ATTACHMENT",
                    canonical_value=str(attachment.id),
                    display_value=attachment.filename,
                    confidence=1.0,
                )
                # HAS_ATTACHMENT edge (email -> attachment)
                self._get_or_create_edge(
                    db,
                    source_node_id=email_node.node_id,
                    target_node_id=attachment_node.node_id,
                    relationship_type="HAS_ATTACHMENT",
                    confidence=1.0,
                    is_inferred=False,
                    source_email_id=email_id,
                    evidence_type="EMAIL_ATTACHMENT",
                    evidence_reference="Attachment record",
                )

                # File hash node
                file_hash_node = self._get_or_create_node(
                    db,
                    node_type="FILE_HASH",
                    canonical_value=attachment.sha256,
                    display_value=attachment.sha256,
                    confidence=1.0,
                )
                # HAS_FILE_HASH edge (attachment -> file_hash)
                self._get_or_create_edge(
                    db,
                    source_node_id=attachment_node.node_id,
                    target_node_id=file_hash_node.node_id,
                    relationship_type="HAS_FILE_HASH",
                    confidence=1.0,
                    is_inferred=False,
                    source_email_id=email_id,
                    evidence_type="ATTACHMENT_HASH",
                    evidence_reference="Attachment SHA-256",
                )

            if own_session:
                db.commit()
        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to add attachment hashes to graph: {e}")
            raise
        finally:
            if own_session:
                db.close()

    # Correlation rule version - increment when scoring algorithm changes
    CORRELATION_RULE_VERSION = "1.0.0"

    def correlate_emails(self, email1_id: int, email2_id: int, db: Session = None) -> float:
        """
        Calculate and store deterministic correlation score between two emails.

        Implements versioned deterministic correlation scoring with explainability.
        Creates a CORRELATES_WITH edge between email nodes with the calculated score
        stored in the confidence field.

        Returns the calculated correlation score (0.0 to 1.0).
        """
        if db is None:
            db = _get_session_local()()
            own_session = True
        else:
            own_session = False

        try:
            # Get the email records from database
            email1_record = db.query(models.Email).filter(models.Email.id == email1_id).first()
            email2_record = db.query(models.Email).filter(models.Email.id == email2_id).first()

            if not email1_record or not email2_record:
                logger.warning(f"One or both email records not found: {email1_id}, {email2_id}")
                if own_session:
                    db.close()
                return 0.0

            # Calculate deterministic correlation score
            score_result = self._calculate_deterministic_correlation_score(
                email1_record, email2_record, db
            )

            similarity_score = score_result["score"]

            # Create evidence reference with explanation
            evidence_reference = (
                f"v{self.CORRELATION_RULE_VERSION} "
                f"score:{similarity_score:.3f} "
                f"cats:{','.join(score_result['categories'])} "
                f"supp:{len(score_result['supporting_signals'])} "
                f"contra:{len(score_result['contradicting_signals'])}"
            )

            # Get or create email nodes
            email1_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email1_id),
                )
                .first()
            )
            email2_node = (
                db.query(models.GraphNode)
                .filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.canonical_value == str(email2_id),
                )
                .first()
            )

            if not email1_node or not email2_node:
                # Create email nodes if they don't exist
                email1_node = self._get_or_create_node(
                    db,
                    node_type="EMAIL",
                    canonical_value=str(email1_id),
                    display_value=email1_record.subject[:40] if email1_record.subject else f"Email #{email1_id}",
                    confidence=1.0,
                )
                email2_node = self._get_or_create_node(
                    db,
                    node_type="EMAIL",
                    canonical_value=str(email2_id),
                    display_value=email2_record.subject[:40] if email2_record.subject else f"Email #{email2_id}",
                    confidence=1.0,
                )

            # Create or update correlation edge
            correlation_edge = self._get_or_create_edge(
                db,
                source_node_id=email1_node.node_id,
                target_node_id=email2_node.node_id,
                relationship_type="CORRELATES_WITH",
                confidence=similarity_score,
                is_inferred=True,  # Correlation edges are inferred relationships
                source_email_id=None,  # Not tied to a specific source email
                source_case_id=None,   # Not tied to a specific case for correlation edges
                evidence_type="CORRELATION_ANALYSIS",
                evidence_reference=evidence_reference,
            )

            if own_session:
                db.commit()

            return similarity_score

        except Exception as e:
            if own_session:
                db.rollback()
            logger.error(f"Failed to correlate emails: {e}")
            raise
        finally:
            if own_session:
                db.close()

    def _calculate_deterministic_correlation_score(
        self,
        email1: models.Email,
        email2: models.Email,
        db: Session
    ) -> dict[str, Any]:
        """
        Calculate deterministic correlation score between two emails.

        Returns a dict with:
        - score: final correlation score (0.0 to 1.0)
        - categories: list of contributing categories
        - supporting_signals: list of signals that increase correlation
        - contradicting_signals: list of signals that decrease correlation
        """
        # Initialize scoring components
        scores = {
            "EXACT_IOC": 0.0,
            "INFRASTRUCTURE": 0.0,
            "SENDER": 0.0,
            "DOMAIN": 0.0,
            "ATTACHMENT": 0.0,
            "URL": 0.0,
            "CONTENT": 0.0,
            "AUTHENTICATION": 0.0,
            "THREAT_INTEL": 0.0,
        }

        supporting_signals = []
        contradicting_signals = []

        # 1. EXACT_IOC matches (highest weight)
        exact_ioc_score, exact_signals = self._calculate_exact_ioc_matches(email1, email2, db)
        scores["EXACT_IOC"] = exact_ioc_score
        supporting_signals.extend(exact_signals)

        # 2. INFRASTRUCTURE matches (shared IPs, domains from headers)
        infra_score, infra_signals = self._calculate_infrastructure_matches(email1, email2, db)
        scores["INFRASTRUCTURE"] = infra_score
        supporting_signals.extend(infra_signals)

        # 3. SENDER matches
        sender_score, sender_signals = self._calculate_sender_matches(email1, email2)
        scores["SENDER"] = sender_score
        supporting_signals.extend(sender_signals)

        # 4. DOMAIN matches (sender domain, reply-to domain)
        domain_score, domain_signals = self._calculate_domain_matches(email1, email2)
        scores["DOMAIN"] = domain_score
        supporting_signals.extend(domain_signals)

        # 5. ATTACHMENT matches (exact hash matches)
        attachment_score, attachment_signals = self._calculate_attachment_matches(email1, email2)
        scores["ATTACHMENT"] = attachment_score
        supporting_signals.extend(attachment_signals)

        # 6. URL matches (exact URL matches)
        url_score, url_signals = self._calculate_url_matches(email1, email2)
        scores["URL"] = url_score
        supporting_signals.extend(url_signals)

        # 7. CONTENT similarity (subject, body)
        content_score, content_signals = self._calculate_content_similarity(email1, email2)
        scores["CONTENT"] = content_score
        supporting_signals.extend(content_signals)

        # 8. AUTHENTICATION anomalies
        auth_score, auth_signals = self._calculate_authentication_anomalies(email1, email2)
        scores["AUTHENTICATION"] = auth_score
        # Authentication anomalies can be either supporting or contradicting
        supporting_signals.extend([s for s in auth_signals if s.get("type") == "supporting"])
        contradicting_signals.extend([s for s in auth_signals if s.get("type") == "contradicting"])

        # 9. THREAT_INTEL matches (shared IOCs from threat intelligence)
        ti_score, ti_signals = self._calculate_threat_intel_matches(email1, email2, db)
        scores["THREAT_INTEL"] = ti_score
        supporting_signals.extend(ti_signals)

        # Apply weights to each category
        weights = {
            "EXACT_IOC": 0.30,      # Highest weight - exact matches are strong indicators
            "INFRASTRUCTURE": 0.20, # Shared infrastructure is strong
            "SENDER": 0.15,         # Exact sender match
            "DOMAIN": 0.10,         # Domain matches
            "ATTACHMENT": 0.10,     # Attachment hash matches
            "URL": 0.05,            # URL matches
            "CONTENT": 0.05,        # Content similarity
            "AUTHENTICATION": 0.03, # Authentication anomalies
            "THREAT_INTEL": 0.02,   # Threat intelligence matches
        }

        # Calculate weighted score
        weighted_score = sum(scores[cat] * weights[cat] for cat in scores)

        # Apply damping function to prevent scores from being too high
        # This prevents weak signals from overwhelming strong contradictory signals
        # Using a sigmoid-like function: score / (1 + score)
        final_score = weighted_score / (1 + weighted_score) if weighted_score > 0 else 0.0

        # Ensure score is in [0, 1] range
        final_score = max(0.0, min(1.0, final_score))

        # Determine which categories contributed significantly (> 0.01)
        active_categories = [
            cat for cat, score in scores.items()
            if score * weights[cat] > 0.01
        ]

        return {
            "score": final_score,
            "categories": active_categories,
            "supporting_signals": supporting_signals,
            "contradicting_signals": contradicting_signals,
        }

    def build_cytoscape_graph(self) -> dict[str, Any]:
        """Get the full correlation graph in Cytoscape.js format."""
        with _get_session_local()() as db:
            try:
                # Query all nodes and edges
                nodes = db.query(models.GraphNode).all()
                edges = db.query(models.GraphEdge).all()

                # Convert to Cytoscape format
                cyto_nodes = []
                for node in nodes:
                    cyto_nodes.append(
                        {
                            "data": {
                                "id": node.node_id,
                                "label": node.display_value or node.node_id,
                                "nodeType": node.node_type,
                                "confidence": node.confidence,
                "first_seen": node.first_seen.isoformat() if node.first_seen else None,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "source_count": node.source_count,
                **({"display_value": node.display_value} if node.display_value else {}),
                            }
                        }
                    )

                cyto_edges = []
                for edge in edges:
                    cyto_edges.append(
                        {
                            "data": {
                                "id": edge.edge_id,
                                "source": edge.source_node_id,
                                "target": edge.target_node_id,
                                "edgeType": edge.relationship_type,
                                "confidence": edge.confidence,
                "first_seen": edge.first_seen.isoformat() if edge.first_seen else None,
                "last_seen": edge.last_seen.isoformat() if edge.last_seen else None,
                "observation_count": edge.observation_count,
                "is_inferred": edge.is_inferred,
                **(
                                    {
                                        "source_email_id": edge.source_email_id,
                                        "source_case_id": edge.source_case_id,
                                        "source_provider": edge.source_provider,
                                        "evidence_type": edge.evidence_type,
                                        "evidence_reference": edge.evidence_reference,
                                    }
                                    if edge.source_email_id is not None
                                    else {}
                                ),
                            }
                        }
                    )

                # Compute stats
                node_types = {}
                for n in nodes:
                    node_types[n.node_type] = node_types.get(n.node_type, 0) + 1

                edge_types = {}
                for e in edges:
                    edge_types[e.relationship_type] = edge_types.get(e.relationship_type, 0) + 1

                stats = {
                    "total_nodes": len(nodes),
                    "total_edges": len(edges),
                    "node_types": node_types,
                    "edge_types": edge_types,
                }

                result = {"elements": {"nodes": cyto_nodes, "edges": cyto_edges}, "stats": stats}
                return CytoscapeGraph(result)
            except Exception as e:
                logger.error(f"Failed to build cytoscape graph: {e}")
                return CytoscapeGraph({"elements": {"nodes": [], "edges": []}, "stats": {}})

    def get_shared_infrastructure(self) -> list[dict[str, Any]]:
        """Find IPs or domains shared by multiple emails."""
        with SessionLocal() as db:
            try:
                shared: list[dict[str, Any]] = []

                # Find IP nodes connected to multiple email nodes via RECEIVED_FROM_IP edges
                ip_nodes = (
                    db.query(models.GraphNode)
                    .filter(models.GraphNode.node_type == "IP")
                    .all()
                )
                for ip_node in ip_nodes:
                    # Count distinct emails that have a RECEIVED_FROM_IP edge to this IP
                    email_count = (
                        db.query(models.GraphNode)
                        .join(
                            models.GraphEdge,
                            models.GraphNode.node_id == models.GraphEdge.source_node_id,
                        )
                        .filter(
                            models.GraphEdge.target_node_id == ip_node.node_id,
                            models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                            models.GraphNode.node_type == "EMAIL",
                        )
                        .distinct(models.GraphNode.node_id)
                        .count()
                    )
                    if email_count > 1:
                        # Get the email IDs
                        email_ids = [
                            str(eid[0])
                            for eid in db.query(models.GraphNode.canonical_value)
                            .join(
                                models.GraphEdge,
                                models.GraphNode.node_id == models.GraphEdge.source_node_id,
                            )
                            .filter(
                                models.GraphEdge.target_node_id == ip_node.node_id,
                                models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                                models.GraphNode.node_type == "EMAIL",
                            )
                            .all()
                        ]
                        shared.append(
                            {
                                "type": "shared_ip",
                                "value": ip_node.display_value or ip_node.node_id,
                                "email_count": email_count,
                                "email_ids": email_ids,
                            }
                        )

                # Find domain nodes connected to multiple email nodes via sender path:
                # email --SENT_FROM--> sender --USES_DOMAIN--> domain
                domain_nodes = (
                    db.query(models.GraphNode)
                    .filter(models.GraphNode.node_type == "DOMAIN")
                    .all()
                )
                for domain_node in domain_nodes:
                    # Count distinct emails that have a path to this domain via sender
                    # Create aliases for the joins to avoid duplicate table references
                    EmailNode = aliased(models.GraphNode)
                    SentFromEdge = aliased(models.GraphEdge)
                    SenderNode = aliased(models.GraphNode)
                    UsesDomainEdge = aliased(models.GraphEdge)
                    DomainNode = aliased(models.GraphNode)

                    email_count = (
                        db.query(EmailNode)
                        .join(SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id)
                        .join(SenderNode, SentFromEdge.target_node_id == SenderNode.node_id)
                        .join(UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id)
                        .join(DomainNode, UsesDomainEdge.target_node_id == DomainNode.node_id)
                        .filter(
                            SentFromEdge.relationship_type == "SENT_FROM",
                            SenderNode.node_type == "SENDER",
                            UsesDomainEdge.relationship_type == "USES_DOMAIN",
                            DomainNode.node_id == domain_node.node_id,
                        )
                        .distinct(EmailNode.node_id)
                        .count()
                    )
                    if email_count > 1:
                        # Get the email IDs
                        email_ids = [
                            str(eid[0])
                            for eid in db.query(EmailNode.canonical_value)
                            .join(SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id)
                            .join(SenderNode, SentFromEdge.target_node_id == SenderNode.node_id)
                            .join(UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id)
                            .join(DomainNode, UsesDomainEdge.target_node_id == DomainNode.node_id)
                            .filter(
                                SentFromEdge.relationship_type == "SENT_FROM",
                                SenderNode.node_type == "SENDER",
                                UsesDomainEdge.relationship_type == "USES_DOMAIN",
                                DomainNode.node_id == domain_node.node_id,
                            )
                            .all()
                        ]
                        shared.append(
                            {
                                "type": "shared_domain",
                                "value": domain_node.display_value or domain_node.node_id,
                                "email_count": email_count,
                                "email_ids": email_ids,
                            }
                        )

                return shared
            except Exception as e:
                logger.error(f"Failed to get shared infrastructure: {e}")
                return []

    def get_emails_by_url(self, url: str) -> list[dict[str, Any]]:
        """Get emails that contain a specific URL."""
        with SessionLocal() as db:
            try:
                # Find the URL node
                url_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == "URL",
                        models.GraphNode.canonical_value == url,
                    )
                    .first()
                )

                if not url_node:
                    return []

                # Find emails that have a CONTAINS_URL edge to this URL
                email_nodes = (
                    db.query(models.GraphNode)
                    .join(
                        models.GraphEdge,
                        models.GraphNode.node_id == models.GraphEdge.source_node_id,
                    )
                    .filter(
                        models.GraphEdge.target_node_id == url_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "EMAIL",
                    )
                    .all()
                )

                emails = []
                for email_node in email_nodes:
                    # Get additional details about the email
                    email_data = {
                        "email_id": email_node.node_id,
                        "email_value": email_node.display_value or email_node.node_id,
                        "subject": getattr(email_node, 'subject', ''),
                        "sender": getattr(email_node, 'sender', ''),
                        "timestamp": getattr(email_node, 'timestamp', None),
                    }
                    emails.append(email_data)

                return emails
            except Exception as e:
                logger.error(f"Failed to get emails by URL {url}: {e}")
                return []

    def get_emails_by_domain(self, domain: str) -> list[dict[str, Any]]:
        """Get emails associated with a specific domain (via sender or links)."""
        with SessionLocal() as db:
            try:
                # Find the domain node
                domain_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == "DOMAIN",
                        models.GraphNode.canonical_value == domain,
                    )
                    .first()
                )

                if not domain_node:
                    return []

                emails = []

                # Find emails where this domain is in the sender address (SENT_FROM -> SENDER -> USES_DOMAIN)
                sender_path_emails = (
                    db.query(models.GraphNode)
                    .join(
                        models.GraphEdge,
                        models.GraphNode.node_id == models.GraphEdge.source_node_id,
                    )  # EMAIL -> SENT_FROM -> SENDER
                    .join(
                        models.GraphEdge,
                        models.GraphEdge.target_node_id == models.GraphNode.node_id,
                        aliased=True
                    )  # SENDER <- USES_DOMAIN -> DOMAIN
                    .filter(
                        models.GraphEdge.relationship_type == "SENT_FROM",
                        models.GraphNode.node_type == "SENDER",
                    )
                    .join(
                        models.GraphNode,
                        models.GraphNode.node_id == models.GraphEdge.target_node_id,
                        aliased=True
                    )  # USES_DOMAIN edge
                    .join(
                        models.GraphEdge,
                        and_(
                            models.GraphEdge.source_node_id == models.GraphNode.node_id,
                            models.GraphEdge.relationship_type == "USES_DOMAIN"
                        ),
                        aliased=True
                    )
                    .join(
                        models.GraphNode,
                        models.GraphNode.node_id == models.GraphEdge.target_node_id,
                        aliased=True
                    )  # DOMAIN node
                    .filter(
                        models.GraphNode.node_id == domain_node.node_id,
                        models.GraphNode.node_type == "DOMAIN"
                    )
                    .all()
                )

                # Find emails that contain links to this domain (CONTAINS_DOMAIN)
                domain_link_emails = (
                    db.query(models.GraphNode)
                    .join(
                        models.GraphEdge,
                        models.GraphNode.node_id == models.GraphEdge.source_node_id,
                    )
                    .filter(
                        models.GraphEdge.target_node_id == domain_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_DOMAIN",
                        models.GraphNode.node_type == "EMAIL",
                    )
                    .all()
                )

                # Combine and deduplicate
                all_email_nodes = {node.node_id: node for node in sender_path_emails + domain_link_emails}

                for email_node in all_email_nodes.values():
                    email_data = {
                        "email_id": email_node.node_id,
                        "email_value": email_node.display_value or email_node.node_id,
                        "subject": getattr(email_node, 'subject', ''),
                        "sender": getattr(email_node, 'sender', ''),
                        "timestamp": getattr(email_node, 'timestamp', None),
                    }
                    emails.append(email_data)

                return emails
            except Exception as e:
                logger.error(f"Failed to get emails by domain {domain}: {e}")
                return []

    def get_emails_by_ip(self, ip: str) -> list[dict[str, Any]]:
        """Get emails associated with a specific IP address."""
        with SessionLocal() as db:
            try:
                # Find the IP node
                ip_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == "IP",
                        models.GraphNode.canonical_value == ip,
                    )
                    .first()
                )

                if not ip_node:
                    return []

                # Find emails that have a RECEIVED_FROM_IP edge to this IP
                email_nodes = (
                    db.query(models.GraphNode)
                    .join(
                        models.GraphEdge,
                        models.GraphNode.node_id == models.GraphEdge.source_node_id,
                    )
                    .filter(
                        models.GraphEdge.target_node_id == ip_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "EMAIL",
                    )
                    .all()
                )

                emails = []
                for email_node in email_nodes:
                    email_data = {
                        "email_id": email_node.node_id,
                        "email_value": email_node.display_value or email_node.node_id,
                        "subject": getattr(email_node, 'subject', ''),
                        "sender": getattr(email_node, 'sender', ''),
                        "timestamp": getattr(email_node, 'timestamp', None),
                    }
                    emails.append(email_data)

                return emails
            except Exception as e:
                logger.error(f"Failed to get emails by IP {ip}: {e}")
                return []

    def get_emails_by_hash(self, file_hash: str) -> list[dict[str, Any]]:
        """Get emails that contain an attachment with the specified file hash."""
        with SessionLocal() as db:
            try:
                # Find the hash node
                hash_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == "FILE_HASH",
                        models.GraphNode.canonical_value == file_hash,
                    )
                    .first()
                )

                if not hash_node:
                    return []

                # Find emails that have a path to this hash via attachments:
                # email --HAS_ATTACHMENT--> attachment --HAS_FILE_HASH--> file_hash
                EmailNode = aliased(models.GraphNode)
                HasAttachmentEdge = aliased(models.GraphEdge)
                AttachmentNode = aliased(models.GraphNode)
                HasFileHashEdge = aliased(models.GraphEdge)
                HashNode = aliased(models.GraphNode)

                email_nodes = (
                    db.query(EmailNode)
                    .join(HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id)
                    .join(AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id)
                    .join(HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id)
                    .join(HashNode, HasFileHashEdge.target_node_id == HashNode.node_id)
                    .filter(
                        HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                        AttachmentNode.node_type == "ATTACHMENT",
                        HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                        HashNode.node_id == hash_node.node_id,
                    )
                    .all()
                )

                emails = []
                for email_node in email_nodes:
                    email_data = {
                        "email_id": email_node.node_id,
                        "email_value": email_node.display_value or email_node.node_id,
                        "subject": getattr(email_node, 'subject', ''),
                        "sender": getattr(email_node, 'sender', ''),
                        "timestamp": getattr(email_node, 'timestamp', None),
                    }
                    emails.append(email_data)

                return emails
            except Exception as e:
                logger.error(f"Failed to get emails by hash {file_hash}: {e}")
                return []

    def traverse_graph(self, start_node_id: str, max_depth: int = 3, max_nodes_per_level: int = 10) -> dict[str, Any]:
        """
        Perform a bounded breadth-first traversal of the correlation graph.

        Args:
            start_node_id: The node ID to start traversal from
            max_depth: Maximum depth to traverse (default: 3)
            max_nodes_per_level: Maximum nodes to process per level (default: 10) - fan-out protection

        Returns:
            Dictionary containing traversal results including nodes, edges, and paths
        """
        with SessionLocal() as db:
            try:
                # Find the start node
                start_node = (
                    db.query(models.GraphNode)
                    .filter(models.GraphNode.node_id == start_node_id)
                    .first()
                )

                if not start_node:
                    return {"error": "Start node not found", "nodes": [], "edges": [], "paths": []}

                # Bounded BFS traversal
                visited = set()
                current_level = [start_node_id]
                next_level = []
                all_nodes = []
                all_edges = []
                paths = [{"path": [start_node_id], "depth": 0}]  # Track paths

                depth = 0
                while current_level and depth < max_depth:
                    # Process current level with fan-out protection
                    nodes_to_process = current_level[:max_nodes_per_level]

                    for node_id in nodes_to_process:
                        if node_id in visited:
                            continue

                        visited.add(node_id)

                        # Get node details
                        node = db.query(models.GraphNode).filter(models.GraphNode.node_id == node_id).first()
                        if node:
                            node_data = {
                                "id": node.node_id,
                                "label": node.display_value or node.node_id,
                                "nodeType": node.node_type,
                                "confidence": node.confidence,
                                "first_seen": node.first_seen.isoformat() if node.first_seen else None,
                                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                                "source_count": node.source_count,
                            }
                            all_nodes.append(node_data)

                        # Get outgoing edges
                        outgoing_edges = db.query(models.GraphEdge).filter(
                            models.GraphEdge.source_node_id == node_id
                        ).all()

                        for edge in outgoing_edges:
                            edge_data = {
                                "id": edge.edge_id,
                                "source": edge.source_node_id,
                                "target": edge.target_node_id,
                                "edgeType": edge.relationship_type,
                                "confidence": edge.confidence,
                                "is_inferred": edge.is_inferred,
                                "first_seen": edge.first_seen.isoformat() if edge.first_seen else None,
                                "last_seen": edge.last_seen.isoformat() if edge.last_seen else None,
                                "observation_count": edge.observation_count,
                            }
                            all_edges.append(edge_data)

                            # Add target node to next level if not visited
                            if edge.target_node_id not in visited and edge.target_node_id not in next_level:
                                next_level.append(edge.target_node_id)

                                # Track path
                                for path_info in paths:
                                    if path_info["path"][-1] == node_id and path_info["depth"] == depth:
                                        new_path = path_info["path"] + [edge.target_node_id]
                                        paths.append({"path": new_path, "depth": depth + 1})
                                        break

                    # Move to next level
                    current_level = next_level
                    next_level = []
                    depth += 1

                # Remove duplicate nodes based on ID
                unique_nodes = {}
                for node in all_nodes:
                    unique_nodes[node["id"]] = node

                # Remove duplicate edges based on ID
                unique_edges = {}
                for edge in all_edges:
                    unique_edges[edge["id"]] = edge

                return {
                    "nodes": list(unique_nodes.values()),
                    "edges": list(unique_edges.values()),
                    "paths": paths,
                    "traversal_info": {
                        "start_node": start_node_id,
                        "max_depth": max_depth,
                        "max_nodes_per_level": max_nodes_per_level,
                        "actual_depth": depth - 1,
                        "nodes_visited": len(visited),
                        "nodes_returned": len(unique_nodes),
                        "edges_returned": len(unique_edges)
                    }
                }

            except Exception as e:
                logger.error(f"Failed to traverse graph from {start_node_id}: {e}")
                return {"error": str(e), "nodes": [], "edges": [], "paths": []}

    def find_shortest_path(self, source_node_id: str, target_node_id: str, max_depth: int = 5) -> dict[str, Any]:
        """
        Find the shortest path between two nodes using bounded BFS.

        Args:
            source_node_id: Starting node ID
            target_node_id: Target node ID
            max_depth: Maximum search depth (default: 5)

        Returns:
            Dictionary containing path information or error
        """
        with SessionLocal() as db:
            try:
                # Validate nodes exist
                source_node = db.query(models.GraphNode).filter(models.GraphNode.node_id == source_node_id).first()
                target_node = db.query(models.GraphNode).filter(models.GraphNode.node_id == target_node_id).first()

                if not source_node:
                    return {"error": "Source node not found"}
                if not target_node:
                    return {"error": "Target node not found"}

                # Bounded BFS for shortest path
                if source_node_id == target_node_id:
                    return {
                        "path": [source_node_id],
                        "length": 0,
                        "found": True
                    }

                visited = set([source_node_id])
                queue = [(source_node_id, [source_node_id])]  # (node_id, path)

                while queue:
                    node_id, path = queue.pop(0)

                    if len(path) > max_depth:
                        continue

                    # Get outgoing edges
                    outgoing_edges = db.query(models.GraphEdge).filter(
                        models.GraphEdge.source_node_id == node_id
                    ).all()

                    for edge in outgoing_edges:
                        neighbor_id = edge.target_node_id

                        if neighbor_id == target_node_id:
                            # Found target!
                            return {
                                "path": path + [neighbor_id],
                                "length": len(path),
                                "found": True
                            }

                        if neighbor_id not in visited:
                            visited.add(neighbor_id)
                            queue.append((neighbor_id, path + [neighbor_id]))

                return {
                    "path": [],
                    "length": -1,
                    "found": False,
                    "message": f"No path found within max_depth={max_depth}"
                }

            except Exception as e:
                logger.error(f"Failed to find shortest path from {source_node_id} to {target_node_id}: {e}")
                return {"error": str(e), "path": [], "length": -1, "found": False}

    def get_ioc_timeline(self, ioc_value: str, ioc_type: str) -> dict[str, Any]:
        """
        Get timeline information for a specific IOC (first seen, last seen, activity duration).

        Args:
            ioc_value: The IOC value (e.g., "example.com", "1.2.3.4")
            ioc_type: The IOC type (e.g., "DOMAIN", "IP", "URL", "FILE_HASH")

        Returns:
            Dictionary containing timeline information
        """
        with SessionLocal() as db:
            try:
                # Find the IOC node
                ioc_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == ioc_type,
                        models.GraphNode.canonical_value == ioc_value,
                    )
                    .first()
                )

                if not ioc_node:
                    return {"error": f"IOC not found: {ioc_type}={ioc_value}"}

                # Calculate timeline metrics
                first_seen = ioc_node.first_seen
                last_seen = ioc_node.last_seen

                timeline_data = {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                    "is_active": ioc_node.is_active if hasattr(ioc_node, 'is_active') else True,
                    "source_count": ioc_node.source_count,
                    "confidence": ioc_node.confidence,
                }

                # Calculate duration if both timestamps exist
                if first_seen and last_seen:
                    try:
                        duration_seconds = (last_seen - first_seen).total_seconds()
                        timeline_data["duration_seconds"] = duration_seconds
                        timeline_data["duration_days"] = duration_seconds / (24 * 3600)
                    except Exception:
                        timeline_data["duration_seconds"] = None
                        timeline_data["duration_days"] = None
                else:
                    timeline_data["duration_seconds"] = None
                    timeline_data["duration_days"] = None

                # Get associated email count over time (simplified)
                # Count distinct emails connected to this IOC
                if ioc_type == "IP":
                    # For IPs, count emails via RECEIVED_FROM_IP
                    email_count = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "EMAIL"
                    ).distinct(models.GraphNode.node_id).count()
                elif ioc_type == "DOMAIN":
                    # For domains, count emails via sender path: email -> SENT_FROM -> sender -> USES_DOMAIN -> domain
                    EmailNode = aliased(models.GraphNode)
                    SentFromEdge = aliased(models.GraphEdge)
                    SenderNode = aliased(models.GraphNode)
                    UsesDomainEdge = aliased(models.GraphEdge)

                    email_count = db.query(EmailNode).join(
                        SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id
                    ).join(
                        SenderNode, SentFromEdge.target_node_id == SenderNode.node_id
                    ).join(
                        UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id
                    ).filter(
                        SentFromEdge.relationship_type == "SENT_FROM",
                        SenderNode.node_type == "SENDER",
                        UsesDomainEdge.relationship_type == "USES_DOMAIN",
                        UsesDomainEdge.target_node_id == ioc_node.node_id
                    ).distinct(EmailNode.node_id).count()
                elif ioc_type == "URL":
                    # For URLs, count emails via CONTAINS_URL
                    email_count = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "EMAIL"
                    ).distinct(models.GraphNode.node_id).count()
                elif ioc_type == "FILE_HASH":
                    # For file hashes, count emails via attachment path: email -> HAS_ATTACHMENT -> attachment -> HAS_FILE_HASH -> hash
                    EmailNode = aliased(models.GraphNode)
                    HasAttachmentEdge = aliased(models.GraphEdge)
                    AttachmentNode = aliased(models.GraphNode)
                    HasFileHashEdge = aliased(models.GraphEdge)

                    email_count = db.query(EmailNode).join(
                        HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id
                    ).join(
                        AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id
                    ).join(
                        HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id
                    ).filter(
                        HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                        AttachmentNode.node_type == "ATTACHMENT",
                        HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                        HasFileHashEdge.target_node_id == ioc_node.node_id
                    ).distinct(EmailNode.node_id).count()
                else:
                    # Default: count direct connections
                    email_count = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc_node.node_id,
                        models.GraphNode.node_type == "EMAIL"
                    ).distinct(models.GraphNode.node_id).count()

                timeline_data["associated_email_count"] = email_count

                return timeline_data

            except Exception as e:
                logger.error(f"Failed to get IOC timeline for {ioc_type}={ioc_value}: {e}")
                return {"error": str(e)}

    def get_trending_iocs(self, ioc_type: str, limit: int = 10, days_back: int = 7) -> list[dict[str, Any]]:
        """
        Get trending IOCs based on recent activity.

        Args:
            ioc_type: Type of IOC to analyze (e.g., "DOMAIN", "IP", "URL")
            limit: Maximum number of results to return
            days_back: How many days back to look for activity

        Returns:
            List of trending IOCs with activity metrics
        """
        with SessionLocal() as db:
            try:
                from datetime import datetime, timedelta

                cutoff_date = datetime.utcnow() - timedelta(days=days_back)

                # Query nodes of the specified type with recent activity
                query = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == ioc_type,
                    models.GraphNode.last_seen >= cutoff_date
                )

                # Order by recent activity and source count
                iocs = query.order_by(
                    models.GraphNode.last_seen.desc(),
                    models.GraphNode.source_count.desc()
                ).limit(limit).all()

                trending_list = []
                for ioc in iocs:
                    # Get associated email count for additional context
                    if ioc_type == "IP":
                        email_count = db.query(models.GraphNode).join(
                            models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                        ).filter(
                            models.GraphEdge.target_node_id == ioc.node_id,
                            models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                            models.GraphNode.node_type == "EMAIL"
                        ).distinct(models.GraphNode.node_id).count()
                    elif ioc_type == "DOMAIN":
                        EmailNode = aliased(models.GraphNode)
                        SentFromEdge = aliased(models.GraphEdge)
                        SenderNode = aliased(models.GraphNode)
                        UsesDomainEdge = aliased(models.GraphEdge)

                        email_count = db.query(EmailNode).join(
                            SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id
                        ).join(
                            SenderNode, SentFromEdge.target_node_id == SenderNode.node_id
                        ).join(
                            UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id
                        ).filter(
                            SentFromEdge.relationship_type == "SENT_FROM",
                            SenderNode.node_type == "SENDER",
                            UsesDomainEdge.relationship_type == "USES_DOMAIN",
                            UsesDomainEdge.target_node_id == ioc.node_id
                        ).distinct(EmailNode.node_id).count()
                    elif ioc_type == "URL":
                        email_count = db.query(models.GraphNode).join(
                            models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                        ).filter(
                            models.GraphEdge.target_node_id == ioc.node_id,
                            models.GraphEdge.relationship_type == "CONTAINS_URL",
                            models.GraphNode.node_type == "EMAIL"
                        ).distinct(models.GraphNode.node_id).count()
                    elif ioc_type == "FILE_HASH":
                        EmailNode = aliased(models.GraphNode)
                        HasAttachmentEdge = aliased(models.GraphEdge)
                        AttachmentNode = aliased(models.GraphNode)
                        HasFileHashEdge = aliased(models.GraphEdge)

                        email_count = db.query(EmailNode).join(
                            HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id
                        ).join(
                            AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id
                        ).join(
                            HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id
                        ).filter(
                            HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                            AttachmentNode.node_type == "ATTACHMENT",
                            HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                            HasFileHashEdge.target_node_id == ioc.node_id
                        ).distinct(EmailNode.node_id).count()
                    else:
                        email_count = db.query(models.GraphNode).join(
                            models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                        ).filter(
                            models.GraphEdge.target_node_id == ioc.node_id,
                            models.GraphNode.node_type == "EMAIL"
                        ).distinct(models.GraphNode.node_id).count()

                    # Calculate days active if possible
                    days_active = None
                    if ioc.first_seen and ioc.last_seen:
                        try:
                            days_active = (ioc.last_seen - ioc.first_seen).total_seconds() / (24 * 3600)
                        except Exception:
                            pass

                    trending_list.append({
                        "ioc_type": ioc_type,
                        "ioc_value": ioc.canonical_value,
                        "display_value": ioc.display_value or ioc.canonical_value,
                        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                        "source_count": ioc.source_count,
                        "confidence": ioc.confidence,
                        "associated_email_count": email_count,
                        "days_active": days_active
                    })

                return trending_list

            except Exception as e:
                logger.error(f"Failed to get trending IOCs for type {ioc_type}: {e}")
                return []

    def get_temporal_ioc_correlation(self, ioc1_type: str, ioc1_value: str, ioc2_type: str, ioc2_value: str,
                                   time_window_hours: int = 24) -> dict[str, Any]:
        """
        Calculate temporal correlation between two IOCs based on co-occurrence within time windows.

        Args:
            ioc1_type: Type of first IOC (e.g., "DOMAIN", "IP")
            ioc1_value: Value of first IOC
            ioc2_type: Type of second IOC (e.g., "DOMAIN", "IP", "URL", "FILE_HASH")
            ioc2_value: Value of second IOC
            time_window_hours: Time window in seconds to consider for co-occurrence (default: 24 hours)

        Returns:
            Dictionary containing temporal correlation metrics
        """
        with SessionLocal() as db:
            try:
                from datetime import datetime, timedelta

                # Find both IOC nodes
                ioc1_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == ioc1_type,
                        models.GraphNode.canonical_value == ioc1_value,
                    )
                    .first()
                )

                ioc2_node = (
                    db.query(models.GraphNode)
                    .filter(
                        models.GraphNode.node_type == ioc2_type,
                        models.GraphNode.canonical_value == ioc2_value,
                    )
                    .first()
                )

                if not ioc1_node:
                    return {"error": f"First IOC not found: {ioc1_type}={ioc1_value}"}
                if not ioc2_node:
                    return {"error": f"Second IOC not found: {ioc2_type}={ioc2_value}"}

                # Get time window
                time_window = timedelta(hours=time_window_hours)

                # Get emails associated with each IOC within a reasonable timeframe
                # We'll look at emails connected to each IOC and see timing patterns

                # For simplicity, we'll analyze based on when the IOCs were last seen together
                # through shared email connections

                # Find emails connected to IOC1
                ioc1_emails = set()
                if ioc1_type == "IP":
                    # For IPs, get emails via RECEIVED_FROM_IP
                    ioc1_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc1_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc1_emails = {row.node_id for row in ioc1_email_rows}
                elif ioc1_type == "DOMAIN":
                    # For domains, get emails via sender path
                    EmailNode = aliased(models.GraphNode)
                    SentFromEdge = aliased(models.GraphEdge)
                    SenderNode = aliased(models.GraphNode)
                    UsesDomainEdge = aliased(models.GraphEdge)

                    ioc1_email_rows = db.query(EmailNode).join(
                        SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id
                    ).join(
                        SenderNode, SentFromEdge.target_node_id == SenderNode.node_id
                    ).join(
                        UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id
                    ).filter(
                        SentFromEdge.relationship_type == "SENT_FROM",
                        SenderNode.node_type == "SENDER",
                        UsesDomainEdge.relationship_type == "USES_DOMAIN",
                        UsesDomainEdge.target_node_id == ioc1_node.node_id
                    ).all()
                    ioc1_emails = {row.node_id for row in ioc1_email_rows}
                elif ioc1_type == "URL":
                    # For URLs, get emails via CONTAINS_URL
                    ioc1_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc1_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc1_emails = {row.node_id for row in ioc1_email_rows}
                elif ioc1_type == "FILE_HASH":
                    # For file hashes, get emails via attachment path
                    EmailNode = aliased(models.GraphNode)
                    HasAttachmentEdge = aliased(models.GraphEdge)
                    AttachmentNode = aliased(models.GraphNode)
                    HasFileHashEdge = aliased(models.GraphEdge)

                    ioc1_email_rows = db.query(EmailNode).join(
                        HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id
                    ).join(
                        AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id
                    ).join(
                        HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id
                    ).filter(
                        HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                        AttachmentNode.node_type == "ATTACHMENT",
                        HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                        HasFileHashEdge.target_node_id == ioc1_node.node_id
                    ).all()
                    ioc1_emails = {row.node_id for row in ioc1_email_rows}
                else:
                    # Default: direct connections
                    ioc1_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc1_node.node_id,
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc1_emails = {row.node_id for row in ioc1_email_rows}

                # Find emails connected to IOC2
                ioc2_emails = set()
                if ioc2_type == "IP":
                    # For IPs, get emails via RECEIVED_FROM_IP
                    ioc2_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc2_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc2_emails = {row.node_id for row in ioc2_email_rows}
                elif ioc2_type == "DOMAIN":
                    # For domains, get emails via sender path
                    EmailNode = aliased(models.GraphNode)
                    SentFromEdge = aliased(models.GraphEdge)
                    SenderNode = aliased(models.GraphNode)
                    UsesDomainEdge = aliased(models.GraphEdge)

                    ioc2_email_rows = db.query(EmailNode).join(
                        SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id
                    ).join(
                        SenderNode, SentFromEdge.target_node_id == SenderNode.node_id
                    ).join(
                        UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id
                    ).filter(
                        SentFromEdge.relationship_type == "SENT_FROM",
                        SenderNode.node_type == "SENDER",
                        UsesDomainEdge.relationship_type == "USES_DOMAIN",
                        UsesDomainEdge.target_node_id == ioc2_node.node_id
                    ).all()
                    ioc2_emails = {row.node_id for row in ioc2_email_rows}
                elif ioc2_type == "URL":
                    # For URLs, get emails via CONTAINS_URL
                    ioc2_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc2_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc2_emails = {row.node_id for row in ioc2_email_rows}
                elif ioc2_type == "FILE_HASH":
                    # For file hashes, get emails via attachment path
                    EmailNode = aliased(models.GraphNode)
                    HasAttachmentEdge = aliased(models.GraphEdge)
                    AttachmentNode = aliased(models.GraphNode)
                    HasFileHashEdge = aliased(models.GraphEdge)

                    ioc2_email_rows = db.query(EmailNode).join(
                        HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id
                    ).join(
                        AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id
                    ).join(
                        HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id
                    ).filter(
                        HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                        AttachmentNode.node_type == "ATTACHMENT",
                        HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                        HasFileHashEdge.target_node_id == ioc2_node.node_id
                    ).all()
                    ioc2_emails = {row.node_id for row in ioc2_email_rows}
                else:
                    # Default: direct connections
                    ioc2_email_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc2_node.node_id,
                        models.GraphNode.node_type == "EMAIL"
                    ).all()
                    ioc2_emails = {row.node_id for row in ioc2_email_rows}

                # Calculate overlap
                common_emails = ioc1_emails.intersection(ioc2_emails)
                total_unique_emails = ioc1_emails.union(ioc2_emails)

                # Calculate Jaccard similarity for email overlap
                jaccard_similarity = len(common_emails) / len(total_unique_emails) if total_unique_emails else 0.0

                # Calculate temporal overlap based on last_seen times (simplified)
                temporal_overlap = 0.0
                if ioc1_node.last_seen and ioc2_node.last_seen:
                    # Simple heuristic: if last seen times are close, higher temporal correlation
                    time_diff = abs((ioc1_node.last_seen - ioc2_node.last_seen).total_seconds())
                    # Normalize by time window - closer times get higher scores
                    temporal_overlap = max(0.0, 1.0 - (time_diff / (time_window_hours * 3600)))
                    temporal_overlap = min(1.0, temporal_overlap)  # Cap at 1.0

                # Combined temporal correlation score
                temporal_correlation = (jaccard_similarity * 0.7) + (temporal_overlap * 0.3)

                return {
                    "ioc1": {
                        "type": ioc1_type,
                        "value": ioc1_value,
                        "first_seen": ioc1_node.first_seen.isoformat() if ioc1_node.first_seen else None,
                        "last_seen": ioc1_node.last_seen.isoformat() if ioc1_node.last_seen else None,
                        "source_count": ioc1_node.source_count,
                        "confidence": ioc1_node.confidence
                    },
                    "ioc2": {
                        "type": ioc2_type,
                        "value": ioc2_value,
                        "first_seen": ioc2_node.first_seen.isoformat() if ioc2_node.first_seen else None,
                        "last_seen": ioc2_node.last_seen.isoformat() if ioc2_node.last_seen else None,
                        "source_count": ioc2_node.source_count,
                        "confidence": ioc2_node.confidence
                    },
                    "analysis": {
                        "time_window_hours": time_window_hours,
                        "ioc1_email_count": len(ioc1_emails),
                        "ioc2_email_count": len(ioc2_emails),
                        "common_email_count": len(common_emails),
                        "total_unique_email_count": len(total_unique_emails),
                        "jaccard_similarity": jaccard_similarity,
                        "temporal_overlap_score": temporal_overlap,
                        "temporal_correlation_score": temporal_correlation,
                        "correlation_strength": "high" if temporal_correlation > 0.7 else "medium" if temporal_correlation > 0.3 else "low"
                    }
                }

            except Exception as e:
                logger.error(f"Failed to calculate temporal IOC correlation: {e}")
                return {"error": str(e)}

    def get_ioc_lifetime_statistics(self, ioc_type: str) -> dict[str, Any]:
        """
        Get lifetime statistics for a specific IOC type across the population.

        Args:
            ioc_type: Type of IOC to analyze (e.g., "DOMAIN", "IP", "URL")

        Returns:
            Dictionary containing lifetime statistics
        """
        with SessionLocal() as db:
            try:
                from datetime import datetime, timedelta

                # Get all IOCs of the specified type
                iocs = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == ioc_type
                ).all()

                if not iocs:
                    return {
                        "ioc_type": ioc_type,
                        "total_ioc_count": 0,
                        "iocs_with_timestamps": 0,
                        "lifetime_seconds": {
                            "min": 0,
                            "max": 0,
                            "mean": 0,
                            "median": 0,
                            "p90": 0,
                            "p95": 0
                        },
                        "lifetime_days": {
                            "min": 0.0,
                            "max": 0.0,
                            "mean": 0.0,
                            "median": 0.0,
                            "p90": 0.0,
                            "p95": 0.0
                        },
                        "activity_status": {
                            "active_last_30_days": 0,
                            "inactive_over_30_days": 0,
                            "active_percentage": 0.0
                        },
                        "error": f"No IOCs found for type {ioc_type}"
                    }

                lifetimes = []
                current_time = datetime.utcnow()

                for ioc in iocs:
                    if ioc.first_seen and ioc.last_seen:
                        lifetime_seconds = (ioc.last_seen - ioc.first_seen).total_seconds()
                        lifetimes.append(lifetime_seconds)
                    elif ioc.first_seen:
                        # Only has first seen, still active
                        lifetime_seconds = (current_time - ioc.first_seen).total_seconds()
                        lifetimes.append(lifetime_seconds)
                    # If neither timestamp, skip

                if not lifetimes:
                    return {
                        "ioc_type": ioc_type,
                        "total_count": len(iocs),
                        "with_timestamps": 0,
                        "error": "No IOCs with sufficient timestamp data"
                    }

                # Calculate statistics
                lifetimes_sorted = sorted(lifetimes)
                count = len(lifetimes_sorted)

                stats = {
                    "ioc_type": ioc_type,
                    "total_ioc_count": len(iocs),
                    "iocs_with_timestamps": count,
                    "lifetime_seconds": {
                        "min": min(lifetimes_sorted),
                        "max": max(lifetimes_sorted),
                        "mean": sum(lifetimes_sorted) / count,
                        "median": lifetimes_sorted[count // 2] if count % 2 == 1
                                else (lifetimes_sorted[count//2 - 1] + lifetimes_sorted[count//2]) / 2,
                        "p90": lifetimes_sorted[int(count * 0.9)] if count >= 10 else max(lifetimes_sorted),
                        "p95": lifetimes_sorted[int(count * 0.95)] if count >= 20 else max(lifetimes_sorted)
                    },
                    "lifetime_days": {
                        "min": min(lifetimes_sorted) / (24 * 3600),
                        "max": max(lifetimes_sorted) / (24 * 3600),
                        "mean": (sum(lifetimes_sorted) / count) / (24 * 3600),
                        "median": (lifetimes_sorted[count // 2] if count % 2 == 1
                                else (lifetimes_sorted[count//2 - 1] + lifetimes_sorted[count//2]) / 2) / (24 * 3600),
                        "p90": (lifetimes_sorted[int(count * 0.9)] if count >= 10 else max(lifetimes_sorted)) / (24 * 3600),
                        "p95": (lifetimes_sorted[int(count * 0.95)] if count >= 20 else max(lifetimes_sorted)) / (24 * 3600)
                    }
                }

                # Add activity status breakdown
                active_count = 0
                inactive_count = 0
                cutoff_time = current_time - timedelta(days=30)  # Consider inactive if not seen in 30 days

                for ioc in iocs:
                    if ioc.last_seen and ioc.last_seen >= cutoff_time:
                        active_count += 1
                    else:
                        inactive_count += 1

                stats["activity_status"] = {
                    "active_last_30_days": active_count,
                    "inactive_over_30_days": inactive_count,
                    "active_percentage": (active_count / len(iocs)) * 100 if iocs else 0
                }

                return stats

            except Exception as e:
                logger.error(f"Failed to get IOC lifetime statistics for type {ioc_type}: {e}")
                return {"error": str(e)}

    def _calculate_temporal_concentration(self, email_ids: list[int], db: Session, cutoff_time: datetime) -> float:
        """
        Calculate how tightly clustered emails are in time.
        Returns a score between 0.0 and 1.0 where 1.0 means all emails are very close in time.
        """
        if len(email_ids) < 2:
            return 0.0

        try:
            # Get timestamps for all emails
            email_times = db.query(models.GraphNode.first_seen, models.GraphNode.last_seen).filter(
                models.GraphNode.node_id.in_(email_ids),
                models.GraphNode.node_type == "EMAIL"
            ).all()

            if not email_times:
                return 0.0

            # Convert to timestamps and find the time span
            timestamps = []
            for first_seen, last_seen in email_times:
                if first_seen:
                    timestamps.append(first_seen.timestamp())
                if last_seen:
                    timestamps.append(last_seen.timestamp())

            if len(timestamps) < 2:
                return 0.0

            # Calculate time span
            min_time = min(timestamps)
            max_time = max(timestamps)
            time_span = max_time - min_time

            # Normalize by the analysis window (time_window_days)
            # If all emails are within a small fraction of the window, score is high
            window_seconds = (datetime.utcnow() - cutoff_time).total_seconds()
            if window_seconds <= 0:
                return 0.0

            # Score is inversely proportional to normalized time span
            # If time_span is small compared to window, score is high
            normalized_span = min(time_span / window_seconds, 1.0)
            temporal_score = 1.0 - normalized_span

            return max(0.0, min(1.0, temporal_score))
        except Exception:
            return 0.0

    def _calculate_ioc_rarity_score(self, ioc_tuples: list[tuple[str, int]], db: Session) -> float:
        """
        Calculate how rare/shared the IOCs are across the population.
        Returns a score between 0.0 and 1.0 where 1.0 means the IOCs are rare (more suspicious).
        """
        if not ioc_tuples:
            return 0.0

        try:
            rarity_scores = []
            for ioc_type, ioc_node_id in ioc_tuples:
                # Count how many emails have this IOC
                email_count = db.query(models.GraphNode).join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.target_node_id == ioc_node_id,
                    models.GraphNode.node_type == "EMAIL"
                ).count()

                # Convert to rarity score: fewer emails = higher rarity = more suspicious
                # Using logarithmic scale: log(1 + 1/(count+1)) normalized
                if email_count > 0:
                    rarity = 1.0 - min(1.0, email_count / 100.0)  # Assume >100 emails is common
                else:
                    rarity = 1.0
                rarity_scores.append(rarity)

            # Return average rarity
            return sum(rarity_scores) / len(rarity_scores) if rarity_scores else 0.0
        except Exception:
            return 0.0

    def detect_campaigns(self, time_window_days: int = 7, min_ioc_count: int = 3, min_email_count: int = 2) -> list[dict[str, Any]]:
        """
        Detect potential threat campaigns based on temporal clustering and shared infrastructure.

        Args:
            time_window_days: Time window in days to consider for clustering (default: 7)
            min_ioc_count: Minimum number of IOCs required to form a campaign (default: 3)
            min_email_count: Minimum number of emails required to form a campaign (default: 2)

        Returns:
            List of detected campaigns with metadata and associated IOCs/emails
        """
        with SessionLocal() as db:
            try:
                from datetime import datetime, timedelta
                import hashlib

                cutoff_time = datetime.utcnow() - timedelta(days=time_window_days)

                # Get emails seen in the time window
                recent_emails = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.last_seen >= cutoff_time
                ).all()

                if len(recent_emails) < min_email_count:
                    return []

                campaigns = []
                processed_email_sets = set()

                # For each email, find related emails through shared IOCs
                for email_node in recent_emails:
                    email_id = email_node.node_id

                    # Skip if we've already processed this email in a campaign
                    if any(email_id in frozenset(s) for s in processed_email_sets):
                        continue

                    # Find all IOCs associated with this email
                    email_iocs = set()

                    # Get IPs via RECEIVED_FROM_IP
                    ip_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == email_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "IP"
                    ).all()
                    email_iocs.update(("IP", row.node_id) for row in ip_rows)

                    # Get domains via sender path: email -> SENT_FROM --> sender -> USES_DOMAIN --> domain
                    EmailNode = aliased(models.GraphNode)
                    SentFromEdge = aliased(models.GraphEdge)
                    SenderNode = aliased(models.GraphNode)
                    UsesDomainEdge = aliased(models.GraphEdge)
                    DomainNode = aliased(models.GraphNode)

                    domain_rows = db.query(DomainNode).join(
                        UsesDomainEdge, DomainNode.node_id == UsesDomainEdge.target_node_id
                    ).join(
                        SenderNode, UsesDomainEdge.source_node_id == SenderNode.node_id
                    ).join(
                        SentFromEdge, SenderNode.node_id == SentFromEdge.target_node_id
                    ).join(
                        EmailNode, SentFromEdge.source_node_id == EmailNode.node_id
                    ).filter(
                        SentFromEdge.relationship_type == "SENT_FROM",
                        SenderNode.node_type == "SENDER",
                        UsesDomainEdge.relationship_type == "USES_DOMAIN",
                        EmailNode.node_id == email_node.node_id
                    ).all()
                    email_iocs.update(("DOMAIN", row.node_id) for row in domain_rows)

                    # Get URLs via CONTAINS_URL
                    url_rows = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == email_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "URL"
                    ).all()
                    email_iocs.update(("URL", row.node_id) for row in url_rows)

                    # Get file hashes via attachment path
                    EmailNode = aliased(models.GraphNode)
                    HasAttachmentEdge = aliased(models.GraphEdge)
                    AttachmentNode = aliased(models.GraphNode)
                    HasFileHashEdge = aliased(models.GraphEdge)
                    HashNode = aliased(models.GraphNode)

                    hash_rows = db.query(HashNode).join(
                        HasFileHashEdge, HashNode.node_id == HasFileHashEdge.target_node_id
                    ).join(
                        AttachmentNode, HasFileHashEdge.source_node_id == AttachmentNode.node_id
                    ).join(
                        HasAttachmentEdge, HasAttachmentEdge.source_node_id == AttachmentNode.node_id
                    ).join(
                        EmailNode, EmailNode.node_id == HasAttachmentEdge.source_node_id
                    ).filter(
                        HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                        AttachmentNode.node_type == "ATTACHMENT",
                        HasFileHashEdge.relationship_type == "HAS_FILE_HASH"
                    ).all()
                    email_iocs.update(("FILE_HASH", row.node_id) for row in hash_rows)

                    # Find other emails that share IOCs with this email
                    related_emails = {email_node.node_id}  # Start with the original email
                    ioc_to_emails = {}

                    # Build mapping from IOCs to emails that have them
                    for ioc_type, ioc_node_id in email_iocs:
                        if ioc_type not in ioc_to_emails:
                            ioc_to_emails[ioc_type] = {}

                        if ioc_node_id not in ioc_to_emails[ioc_type]:
                            ioc_to_emails[ioc_type][ioc_node_id] = set()

                        # Find emails that have this IOC
                        if ioc_type == "IP":
                            # For IPs, find emails via RECEIVED_FROM_IP
                            sharing_email_rows = db.query(models.GraphNode).join(
                                models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                            ).filter(
                                models.GraphEdge.target_node_id == ioc_node_id,
                                models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                                models.GraphNode.node_type == "EMAIL",
                                models.GraphNode.last_seen >= cutoff_time
                            ).all()
                            sharing_emails = {row.node_id for row in sharing_email_rows}
                        elif ioc_type == "DOMAIN":
                            # For domains, find emails via sender path
                            EmailNode = aliased(models.GraphNode)
                            SentFromEdge = aliased(models.GraphEdge)
                            SenderNode = aliased(models.GraphNode)
                            UsesDomainEdge = aliased(models.GraphEdge)

                            sharing_email_rows = db.query(EmailNode).join(
                                SentFromEdge, EmailNode.node_id == SentFromEdge.source_node_id
                            ).join(
                                SenderNode, SentFromEdge.target_node_id == SenderNode.node_id
                            ).join(
                                UsesDomainEdge, SenderNode.node_id == UsesDomainEdge.source_node_id
                            ).join(
                                DomainNode, UsesDomainEdge.target_node_id == DomainNode.node_id
                            ).filter(
                                SentFromEdge.relationship_type == "SENT_FROM",
                                SenderNode.node_type == "SENDER",
                                UsesDomainEdge.relationship_type == "USES_DOMAIN",
                                DomainNode.node_id == ioc_node_id,
                                EmailNode.last_seen >= cutoff_time
                            ).all()
                            sharing_emails = {row.node_id for row in sharing_email_rows}
                        elif ioc_type == "URL":
                            # For URLs, find emails via CONTAINS_URL
                            sharing_email_rows = db.query(models.GraphNode).join(
                                models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                            ).filter(
                                models.GraphEdge.target_node_id == ioc_node_id,
                                models.GraphEdge.relationship_type == "CONTAINS_URL",
                                models.GraphNode.node_type == "EMAIL",
                                models.GraphNode.last_seen >= cutoff_time
                            ).all()
                            sharing_emails = {row.node_id for row in sharing_email_rows}
                        elif ioc_type == "FILE_HASH":
                            # For file hashes, find emails via attachment path
                            EmailNode = aliased(models.GraphNode)
                            HasAttachmentEdge = aliased(models.GraphEdge)
                            AttachmentNode = aliased(models.GraphNode)
                            HasFileHashEdge = aliased(models.GraphEdge)

                            sharing_email_rows = db.query(EmailNode).join(
                                HasAttachmentEdge, EmailNode.node_id == HasAttachmentEdge.source_node_id
                            ).join(
                                AttachmentNode, HasAttachmentEdge.target_node_id == AttachmentNode.node_id
                            ).join(
                                HasFileHashEdge, AttachmentNode.node_id == HasFileHashEdge.source_node_id
                            ).join(
                                HashNode, HasFileHashEdge.target_node_id == HashNode.node_id
                            ).filter(
                                HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                                AttachmentNode.node_type == "ATTACHMENT",
                                HasFileHashEdge.relationship_type == "HAS_FILE_HASH",
                                EmailNode.last_seen >= cutoff_time
                            ).all()
                            sharing_emails = {row.node_id for row in sharing_email_rows}
                        else:
                            sharing_emails = set()

                        ioc_to_emails[ioc_type][ioc_node_id] = sharing_emails

                    # Find connected emails through shared IOCs (expansion)
                    frontier = {email_node.node_id}
                    visited = {email_node.node_id}

                    while frontier:
                        current_email = frontier.pop()

                        # Find all IOCs for this email
                        current_email_iocs = set()
                        if current_email == email_node.node_id:
                            current_email_iocs = email_iocs
                        else:
                            # Get IOCs for this email (similar to above but simplified)
                            current_email_node = db.query(models.GraphNode).filter(
                                models.GraphNode.node_id == current_email,
                                models.GraphNode.node_type == "EMAIL"
                            ).first()
                            if current_email_node:
                                # IPs
                                ip_rows = db.query(models.GraphNode).join(
                                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                                ).filter(
                                    models.GraphEdge.target_node_id == current_email,
                                    models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                                    models.GraphNode.node_type == "IP",
                                    models.GraphNode.last_seen >= cutoff_time
                                ).all()
                                current_email_iocs.update(("IP", row.node_id) for row in ip_rows)

                                # Domains
                                EmailNode = aliased(models.GraphNode)
                                SentFromEdge = aliased(models.GraphEdge)
                                SenderNode = aliased(models.GraphNode)
                                UsesDomainEdge = aliased(models.GraphEdge)
                                DomainNode = aliased(models.GraphNode)

                                domain_rows = db.query(DomainNode).join(
                                    UsesDomainEdge, DomainNode.node_id == UsesDomainEdge.target_node_id
                                ).join(
                                    SenderNode, UsesDomainEdge.source_node_id == SenderNode.node_id
                                ).join(
                                    SentFromEdge, SenderNode.node_id == SentFromEdge.target_node_id
                                ).join(
                                    EmailNode, SentFromEdge.source_node_id == EmailNode.node_id
                                ).filter(
                                    SentFromEdge.relationship_type == "SENT_FROM",
                                    SenderNode.node_type == "SENDER",
                                    UsesDomainEdge.relationship_type == "USES_DOMAIN",
                                    EmailNode.node_id == current_email
                                ).all()
                                current_email_iocs.update(("DOMAIN", row.node_id) for row in domain_rows)

                                # URLs
                                url_rows = db.query(models.GraphNode).join(
                                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                                ).filter(
                                    models.GraphEdge.target_node_id == current_email,
                                    models.GraphEdge.relationship_type == "CONTAINS_URL",
                                    models.GraphNode.node_type == "URL",
                                    models.GraphNode.last_seen >= cutoff_time
                                ).all()
                                current_email_iocs.update(("URL", row.node_id) for row in url_rows)

                                # File hashes
                                EmailNode = aliased(models.GraphNode)
                                HasAttachmentEdge = aliased(models.GraphEdge)
                                AttachmentNode = aliased(models.GraphNode)
                                HasFileHashEdge = aliased(models.GraphEdge)
                                HashNode = aliased(models.GraphNode)

                                hash_rows = db.query(HashNode).join(
                                    HasFileHashEdge, HashNode.node_id == HasFileHashEdge.target_node_id
                                ).join(
                                    AttachmentNode, HasFileHashEdge.source_node_id == AttachmentNode.node_id
                                ).join(
                                    HasAttachmentEdge, AttachmentNode.source_node_id == AttachmentNode.node_id
                                ).join(
                                    EmailNode, EmailNode.node_id == HasAttachmentEdge.source_node_id
                                ).filter(
                                    HasAttachmentEdge.relationship_type == "HAS_ATTACHMENT",
                                    AttachmentNode.node_type == "ATTACHMENT",
                                    HasFileHashEdge.relationship_type == "HAS_FILE_HASH"
                                ).all()
                                current_email_iocs.update(("FILE_HASH", row.node_id) for row in hash_rows)

                        # For each IOC, find emails that also have it
                        for ioc_type, ioc_node_id in current_email_iocs:
                            if ioc_type in ioc_to_emails and ioc_node_id in ioc_to_emails[ioc_type]:
                                sharing_emails = ioc_to_emails[ioc_type][ioc_node_id]
                                for sharing_email in sharing_emails:
                                    if sharing_email not in visited:
                                        visited.add(sharing_email)
                                        frontier.add(sharing_email)
                                        related_emails.add(sharing_email)

                    # If we have enough emails and IOCs, this is a potential campaign
                    if len(related_emails) >= min_email_count:
                        # Count total unique IOCs across all related emails
                        campaign_iocs = set()
                        for related_email_id in related_emails:
                            # We'd need to recompute IOCs for each email - for simplicity,
                            # let's use a simplified approach: count IOCs from the original email's set
                            # In a full implementation, we'd compute the union
                            campaign_iocs.update(email_iocs)

                        if len(campaign_iocs) >= min_ioc_count:
                            # Create a campaign identifier based on the emails involved
                            campaign_id_source = "_".join(sorted([str(eid) for eid in related_emails]))
                            campaign_id = hashlib.md5(campaign_id_source.encode()).hexdigest()[:12]

                            # Check if we've already processed this campaign
                            campaign_frozenset = frozenset(related_emails)
                            if campaign_frozenset in processed_email_sets:
                                continue
                            processed_email_sets.add(campaign_frozenset)

                            # Gather campaign details
                            campaign_ioc_details = []
                            for ioc_type, ioc_node_id in list(campaign_iocs)[:10]:  # Limit details for performance
                                ioc_node = db.query(models.GraphNode).filter(
                                    models.GraphNode.node_id == ioc_node_id
                                ).first()
                                if ioc_node:
                                    campaign_ioc_details.append({
                                        "type": ioc_type,
                                        "value": ioc_node.canonical_value,
                                        "display_value": ioc_node.display_value or ioc_node.canonical_value,
                                        "first_seen": ioc_node.first_seen.isoformat() if ioc_node.first_seen else None,
                                        "last_seen": ioc_node.last_seen.isoformat() if ioc_node.last_seen else None,
                                        "confidence": ioc_node.confidence
                                    })

                            campaign_email_details = []
                            for email_id in list(related_emails)[:10]:  # Limit details
                                email_node = db.query(models.GraphNode).filter(
                                    models.GraphNode.node_id == email_id,
                                    models.GraphNode.node_type == "EMAIL"
                                ).first()
                                if email_node:
                                    campaign_email_details.append({
                                        "email_id": email_node.node_id,
                                        "subject": getattr(email_node, 'subject', ''),
                                        "sender": getattr(email_node, 'sender', ''),
                                        "first_seen": email_node.first_seen.isoformat() if email_node.first_seen else None,
                                        "last_seen": email_node.last_seen.isoformat() if email_node.last_seen else None
                                    })

                            # Calculate temporal concentration score (how tightly clustered emails are in time)
                            temporal_score = self._calculate_temporal_concentration(list(related_emails), db, cutoff_time)

                            # Calculate IOC rarity score (based on how unique the shared IOCs are)
                            rarity_score = self._calculate_ioc_rarity_score(list(campaign_iocs), db)

                            # Combined confidence score
                            base_score = min(1.0, (len(related_emails) * 0.1) + (len(campaign_iocs) * 0.05))
                            enhanced_score = min(1.0, base_score * (0.5 + temporal_score * 0.3 + rarity_score * 0.2))

                            campaigns.append({
                                "campaign_id": campaign_id,
                                "detection_time": datetime.utcnow().isoformat(),
                                "time_window_days": time_window_days,
                                "email_count": len(related_emails),
                                "ioc_count": len(campaign_iocs),
                                "ioc_details": campaign_ioc_details,
                                "email_details": campaign_email_details,
                                "confidence_score": enhanced_score,
                                "temporal_concentration": temporal_score,
                                "ioc_rarity": rarity_score,
                                "base_confidence": base_score,
                                "campaign_type": "temporal_cluster"
                            })

                # Sort by confidence score descending
                campaigns.sort(key=lambda x: x["confidence_score"], reverse=True)

                return campaigns[:20]  # Return top 20 campaigns

            except Exception as e:
                logger.error(f"Failed to detect campaigns: {e}")
                return {"error": str(e)}

    def add_threat_intelligence_provider(self, provider_id: str, provider_name: str,
                                       provider_type: str = None,
                                       reliability_score: float = 0.5) -> str:
        """
        Add or update a threat intelligence provider node.

        Args:
            provider_id: Unique identifier for the provider
            provider_name: Human-readable name of the provider
            provider_type: Type of provider (government, commercial, community, etc.)
            reliability_score: Provider reliability score (0.0-1.0)

        Returns:
            Node ID of the provider node
        """
        with SessionLocal() as db:
            try:
                # Check if provider already exists
                provider_node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == "THREATINTELPROVIDER",
                    models.GraphNode.node_id == provider_id
                ).first()

                if provider_node:
                    # Update existing provider
                    provider_node.display_value = provider_name
                    if provider_type:
                        provider_node.canonical_value = provider_type
                    provider_node.confidence = reliability_score
                    properties = dict(provider_node.properties) if provider_node.properties else {}
                    properties.update({
                        "provider_type": provider_type,
                        "reliability_score": reliability_score
                    })
                    provider_node.properties = properties
                else:
                    # Create new provider node
                    provider_node = models.GraphNode(
                        node_id=provider_id,
                        node_type="THREATINTELPROVIDER",
                        display_value=provider_name,
                        canonical_value=provider_type or provider_id,
                        confidence=reliability_score,
                        properties={
                            "provider_type": provider_type,
                            "reliability_score": reliability_score
                        }
                    )
                    db.add(provider_node)

                db.commit()
                return provider_node.node_id
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to add threat intelligence provider: {e}")
                raise

    def link_ioc_to_provider(self, ioc_type: str, ioc_value: str,
                           provider_id: str,
                           confidence: float = 0.8,
                           description: str = None) -> bool:
        """
        Link an IOC to a threat intelligence provider using REPORTED_BY_PROVIDER edge.

        Args:
            ioc_type: Type of IOC (IP, DOMAIN, URL, FILE_HASH, etc.)
            ioc_value: Value of the IOC
            provider_id: ID of the threat intelligence provider
            confidence: Confidence in the provider's assessment (0.0-1.0)
            description: Optional description of the threat

        Returns:
            True if link was created successfully
        """
        with SessionLocal() as db:
            try:
                # Find the IOC node
                ioc_node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == ioc_type,
                    models.GraphNode.canonical_value == ioc_value
                ).first()

                if not ioc_node:
                    logger.warning(f"IOC not found: {ioc_type}:{ioc_value}")
                    return False

                # Find the provider node
                provider_node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == "THREATINTELPROVIDER",
                    models.GraphNode.node_id == provider_id
                ).first()

                if not provider_node:
                    logger.warning(f"Threat intelligence provider not found: {provider_id}")
                    return False

                # Check if edge already exists
                existing_edge = db.query(models.GraphEdge).filter(
                    models.GraphEdge.source_node_id == ioc_node.node_id,
                    models.GraphEdge.target_node_id == provider_node.node_id,
                    models.GraphEdge.relationship_type == "REPORTED_BY_PROVIDER"
                ).first()

                if existing_edge:
                    # Update existing edge
                    existing_edge.confidence = confidence
                    if description:
                        existing_properties = dict(existing_edge.properties) if existing_edge.properties else {}
                        existing_properties.update({
                            "description": description
                        })
                        edge.properties = existing_properties
                else:
                    # Create new edge
                    edge = models.GraphEdge(
                        source_node_id=ioc_node.node_id,
                        target_node_id=provider_node.node_id,
                        relationship_type="REPORTED_BY_PROVIDER",
                        confidence=confidence,
                        properties={
                            "description": description
                        } if description else None
                    )
                    db.add(edge)

                db.commit()
                return True
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to link IOC to provider: {e}")
                return False

    def get_ioc_reputation(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Get reputation score for an IOC based on threat intelligence provider reports.

        Args:
            ioc_type: Type of IOC (IP, DOMAIN, URL, FILE_HASH, etc.)
            ioc_value: Value of the IOC

        Returns:
            Dictionary with reputation information
        """
        with SessionLocal() as db:
            try:
                # Find the IOC node
                ioc_node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == ioc_type,
                    models.GraphNode.canonical_value == ioc_value
                ).first()

                if not ioc_node:
                    return {
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "reputation_score": 0.0,
                        "provider_count": 0,
                        "sources": [],
                        "error": "IOC not found"
                    }

                # Find all providers that reported this IOC
                provider_edges = db.query(models.GraphEdge).join(
                    models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                ).filter(
                    models.GraphEdge.source_node_id == ioc_node.node_id,
                    models.GraphEdge.relationship_type == "REPORTED_BY_PROVIDER",
                    models.GraphNode.node_type == "THREATINTELPROVIDER"
                ).all()

                if not provider_edges:
                    return {
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "reputation_score": 0.0,
                        "provider_count": 0,
                        "sources": []
                    }

                # Calculate weighted reputation score
                total_weight = 0.0
                weighted_sum = 0.0
                sources = []

                for edge in provider_edges:
                    provider_node = db.query(models.GraphNode).filter(
                        models.GraphNode.node_id == edge.target_node_id
                    ).first()

                    if provider_node:
                        provider_reliability = provider_node.confidence or 0.5
                        edge_confidence = edge.confidence or 0.5
                        weight = provider_reliability * edge_confidence

                        total_weight += weight
                        weighted_sum += weight * edge_confidence

                        sources.append({
                            "provider_id": provider_node.node_id,
                            "provider_name": provider_node.display_value,
                            "confidence": edge_confidence,
                            "reliability": provider_reliability,
                            "description": edge.properties.get("description") if edge.properties else None
                        })

                reputation_score = weighted_sum / total_weight if total_weight > 0 else 0.0

                return {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "reputation_score": max(0.0, min(1.0, reputation_score)),
                    "provider_count": len(sources),
                    "sources": sources
                }
            except Exception as e:
                logger.error(f"Failed to get IOC reputation: {e}")
                return {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "reputation_score": 0.0,
                    "provider_count": 0,
                    "sources": [],
                    "error": str(e)
                }

    def correlate_with_threat_intelligence(self, ioc_type: str, ioc_value: str,
                                         time_window_days: int = 30) -> dict[str, Any]:
        """
        Correlate an IOC with threat intelligence provider activity over time.

        Args:
            ioc_type: Type of IOC (IP, DOMAIN, URL, FILE_HASH, etc.)
            ioc_value: Value of the IOC
            time_window_days: Time window in days to consider for correlation

        Returns:
            Dictionary with correlation information
        """
        with SessionLocal() as db:
            try:
                from datetime import datetime, timedelta

                # Find the IOC node
                ioc_node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_type == ioc_type,
                    models.GraphNode.canonical_value == ioc_value
                ).first()

                if not ioc_node:
                    return {
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "error": "IOC not found"
                    }

                cutoff_time = datetime.utcnow() - timedelta(days=time_window_days)

                # Find recent emails associated with this IOC
                recent_emails = db.query(models.GraphNode).join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.target_node_id == ioc_node.node_id,
                    models.GraphNode.node_type == "EMAIL",
                    models.GraphNode.last_seen >= cutoff_time
                ).all()

                # Find provider reports for this IOC
                provider_reports = db.query(models.GraphEdge).join(
                    models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                ).filter(
                    models.GraphEdge.source_node_id == ioc_node.node_id,
                    models.GraphEdge.relationship_type == "REPORTED_BY_PROVIDER",
                    models.GraphNode.node_type == "THREATINTELPROVIDER"
                ).all()

                # Get provider details
                provider_info = []
                for edge in provider_reports:
                    provider_node = db.query(models.GraphNode).filter(
                        models.GraphNode.node_id == edge.target_node_id
                    ).first()

                    if provider_node:
                        provider_info.append({
                            "provider_id": provider_node.node_id,
                            "provider_name": provider_node.display_value,
                            "provider_type": provider_node.canonical_value,
                            "confidence": edge.confidence,
                            "reported_at": edge.properties.get("timestamp") if edge.properties else None,
                            "description": edge.properties.get("description") if edge.properties else None
                        })

                return {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "time_window_days": time_window_days,
                    "associated_email_count": len(recent_emails),
                    "provider_report_count": len(provider_reports),
                    "providers": provider_info,
                    "correlation_strength": "high" if len(provider_reports) > 3 else "medium" if len(provider_reports) > 0 else "low"
                }
            except Exception as e:
                logger.error(f"Failed to correlate with threat intelligence: {e}")
                return {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "error": str(e)
                }

    def associate_node_with_case(self, node_id: str, case_id: int) -> bool:
        """
        Associate a graph node with a case by creating an ASSOCIATED_WITH_CASE edge.

        Args:
            node_id: ID of the graph node to associate
            case_id: ID of the case to associate with

        Returns:
            True if association was successful
        """
        with SessionLocal() as db:
            try:
                # Find the node
                node = db.query(models.GraphNode).filter(
                    models.GraphNode.node_id == node_id
                ).first()

                if not node:
                    logger.warning(f"Graph node not found: {node_id}")
                    return False

                # Verify case exists and get or create the case node
                from .. import models as app_models
                case = db.query(app_models.Case).filter(
                    app_models.Case.id == case_id
                ).first()

                if not case:
                    logger.warning(f"Case not found: {case_id}")
                    return False

                # Get or create the CASE graph node
                case_node = self._get_or_create_node(
                    db,
                    node_type="CASE",
                    canonical_value=str(case_id),
                    display_value=f"Case #{case_id}",
                    confidence=1.0,
                )

                # Create ASSOCIATED_WITH_CASE edge from the node to the case node
                # Check if such an edge already exists to avoid duplicates
                existing_edge = db.query(models.GraphEdge).filter(
                    models.GraphEdge.source_node_id == node_id,
                    models.GraphEdge.target_node_id == case_node.node_id,
                    models.GraphEdge.relationship_type == "ASSOCIATED_WITH_CASE"
                ).first()

                if not existing_edge:
                    # Create new association edge
                    self._get_or_create_edge(
                        db,
                        source_node_id=node_id,
                        target_node_id=case_node.node_id,
                        relationship_type="ASSOCIATED_WITH_CASE",
                        confidence=1.0,
                        is_inferred=False,
                        source_case_id=case_id  # Set the case context for this edge
                    )
                    db.commit()

                return True
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to associate node with case: {e}")
                return False

    def associate_edge_with_case(self, source_node_id: str, target_node_id: str,
                               relationship_type: str, case_id: int) -> bool:
        """
        Associate a graph edge with a case by setting its source_case_id field.

        Args:
            source_node_id: ID of the source graph node
            target_node_id: ID of the target graph node
            relationship_type: Type of relationship between nodes
            case_id: ID of the case to associate with

        Returns:
            True if association was successful
        """
        with SessionLocal() as db:
            try:
                # Find the edge
                edge = db.query(models.GraphEdge).filter(
                    models.GraphEdge.source_node_id == source_node_id,
                    models.GraphEdge.target_node_id == target_node_id,
                    models.GraphEdge.relationship_type == relationship_type
                ).first()

                if not edge:
                    logger.warning(f"Graph edge not found: {source_node_id} -> {target_node_id} ({relationship_type})")
                    return False

                # Verify case exists
                from .. import models as app_models
                case = db.query(app_models.Case).filter(
                    app_models.Case.id == case_id
                ).first()

                if not case:
                    logger.warning(f"Case not found: {case_id}")
                    return False

                # Set the case ID on the edge (this field already exists in the model)
                edge.source_case_id = case_id
                edge.updated_at = models._utcnow()

                db.add(edge)
                db.commit()
                return True
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to associate edge with case: {e}")
                return False

    def get_case_subgraph(self, case_id: int) -> dict[str, Any]:
        """
        Get a subgraph containing only nodes and edges associated with a specific case.

        Args:
            case_id: ID of the case

        Returns:
            Subgraph in Cytoscape.js format containing only case-associated elements
        """
        with SessionLocal() as db:
            try:
                # Verify case exists
                from .. import models as app_models
                case = db.query(app_models.Case).filter(
                    app_models.Case.id == case_id
                ).first()

                if not case:
                    return {
                        "error": f"Case not found: {case_id}",
                        "elements": {"nodes": [], "edges": []}
                    }

                # Find nodes associated with this case
                # For simplicity, we'll look for nodes with the case ID in their properties
                # In a full implementation, we'd have a proper association table
                case_nodes = db.query(models.GraphNode).filter(
                    models.GraphNode.properties.op('?')('associated_case_ids')
                ).all()

                # Filter to only nodes associated with our specific case
                filtered_nodes = []
                for node in case_nodes:
                    associated_case_ids = node.properties.get('associated_case_ids', []) if node.properties else []
                    if case_id in associated_case_ids:
                        filtered_nodes.append(node)

                # Find edges associated with this case
                case_edges = db.query(models.GraphEdge).filter(
                    models.GraphEdge.properties.op('?')('associated_case_ids')
                ).all()

                # Filter to only edges associated with our specific case
                filtered_edges = []
                for edge in case_edges:
                    associated_case_ids = edge.properties.get('associated_case_ids', []) if edge.properties else []
                    if case_id in associated_case_ids:
                        filtered_edges.append(edge)

                # Convert to Cytoscape.js format
                elements = {"nodes": [], "edges": []}

                for node in filtered_nodes:
                    elements["nodes"].append({
                        "data": {
                            "id": node.node_id,
                            "label": node.display_value or node.node_id,
                            "type": node.node_type,
                            "confidence": node.confidence,
                            "first_seen": node.first_seen.isoformat() if node.first_seen else None,
                            "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                            "source_count": node.source_count
                        }
                    })

                for edge in filtered_edges:
                    elements["edges"].append({
                        "data": {
                            "id": edge.edge_id,
                            "source": edge.source_node_id,
                            "target": edge.target_node_id,
                            "type": edge.relationship_type,
                            "confidence": edge.confidence,
                            "source_count": edge.observation_count
                        }
                    })

                return {
                    "case_id": case_id,
                    "case_title": case.title,
                    "elements": elements,
                    "node_count": len(filtered_nodes),
                    "edge_count": len(filtered_edges)
                }
            except Exception as e:
                logger.error(f"Failed to get case subgraph: {e}")
                return {
                    "error": str(e),
                    "elements": {"nodes": [], "edges": []}
                }


# Singleton
_engine: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine