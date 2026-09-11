"""Correlation graph endpoints.

Provides API endpoints for:
- Adding emails to the correlation graph
- Retrieving the full graph in Cytoscape.js format
- Getting shared infrastructure (IPs/domains used by multiple emails)
- Getting emails associated with specific IOCs (URL, domain, IP, hash)
- Performing bounded graph traversal and path finding
- Getting historical intelligence and IOC timeline information
- Performing temporal correlation analysis and lifetime statistics
- Detecting threat campaigns based on temporal clustering
- Threat hunting with structured query model
"""
import time
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import intersect
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from ..db import get_db
from ..forensics.correlation import get_correlation_engine

# Rate limiting storage (in production, use Redis or similar)
_request_counts = defaultdict(list)
_RATE_LIMIT_WINDOW = 60  # 1 minute window
_RATE_LIMIT_MAX_REQUESTS = 30  # max requests per window


def _check_rate_limit(client_id: str) -> bool:
    """Check if client has exceeded rate limit."""
    now = time.time()
    # Clean old requests
    _request_counts[client_id] = [
        req_time for req_time in _request_counts[client_id]
        if now - req_time < _RATE_LIMIT_WINDOW
    ]

    # Check if under limit
    if len(_request_counts[client_id]) >= _RATE_LIMIT_MAX_REQUESTS:
        return False

    # Add current request
    _request_counts[client_id].append(now)
    return True


async def rate_limit_dependency(request: Request):
    """Dependency to enforce rate limiting."""
    client_id = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )


# Threat Hunting Query Models
class IOCQuery(BaseModel):
    """Model for querying specific IOCs"""
    type: str = Field(..., description="IOC type (IP, DOMAIN, URL, FILE_HASH)")
    value: str = Field(..., description="IOC value")


class TimeWindow(BaseModel):
    """Model for time window constraints"""
    hours: Optional[int] = Field(None, description="Lookback hours")
    days: Optional[int] = Field(None, description="Lookback days")
    start_time: Optional[str] = Field(None, description="ISO format start time")
    end_time: Optional[str] = Field(None, description="ISO format end time")


class EmailFilter(BaseModel):
    """Model for email-specific filters"""
    sender_domain: Optional[str] = Field(None, description="Filter by sender domain")
    subject_contains: Optional[str] = Field(None, description="Filter by subject text")
    has_attachment: Optional[bool] = Field(None, description="Filter by attachment presence")
    has_url: Optional[bool] = Field(None, description="Filter by URL presence")
    has_ip: Optional[bool] = Field(None, description="Filter by IP presence")


class ThreatHuntQuery(BaseModel):
    """Structured threat hunting query model"""
    iocs: List[IOCQuery] = Field(default_factory=list, description="List of IOCs to include")
    time_window: Optional[TimeWindow] = Field(None, description="Time window for search")
    email_filters: Optional[EmailFilter] = Field(None, description="Email-specific filters")
    min_confidence: Optional[float] = Field(0.5, description="Minimum confidence score (0.0-1.0)")
    max_results: Optional[int] = Field(100, description="Maximum results to return")
    include_correlated: Optional[bool] = Field(True, description="Include correlated emails")
    include_campaigns: Optional[bool] = Field(False, description="Include detected campaigns")


router = APIRouter(prefix="/api/graph", tags=["correlation"])


@router.post("/email/{email_id}", status_code=status.HTTP_200_OK)
def add_email_to_graph(email_id: int, db: Session = Depends(get_db)):
    """Add an email and its relationships to the correlation graph."""
    engine = get_correlation_engine()
    # Fetch the email from the database to get all its data
    from .. import models

    email = db.query(models.Email).filter(models.Email.id == email_id).first()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with id {email_id} not found",
        )

    # Convert email ORM object to dict for the correlation engine
    email_data = {
        "id": email.id,
        "sender": email.sender,
        "subject": email.subject,
        "case_id": email.case_id,
    }
    try:
        engine.add_email(email_data, db=db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"status": "success"}


@router.get("", response_model=dict)
def get_graph(
    request: Request,
    _: None = Depends(rate_limit_dependency)
):
    """Get the full correlation graph in Cytoscape.js format."""
    engine = get_correlation_engine()
    graph = engine.build_cytoscape_graph()
    return graph


@router.get("/shared", response_model=list)
def get_shared_infrastructure(
    request: Request,
    _: None = Depends(rate_limit_dependency)
):
    """Get IPs and domains shared by multiple emails."""
    engine = get_correlation_engine()
    return engine.get_shared_infrastructure()


@router.get("/url/{url:path}", response_model=list)
def get_emails_by_url(url: str):
    """Get emails that contain a specific URL."""
    engine = get_correlation_engine()
    return engine.get_emails_by_url(url)


@router.get("/domain/{domain}", response_model=list)
def get_emails_by_domain(domain: str):
    """Get emails associated with a specific domain."""
    engine = get_correlation_engine()
    return engine.get_emails_by_domain(domain)


@router.get("/ip/{ip}", response_model=list)
def get_emails_by_ip(ip: str):
    """Get emails associated with a specific IP address."""
    engine = get_correlation_engine()
    return engine.get_emails_by_ip(ip)


@router.get("/hash/{file_hash}", response_model=list)
def get_emails_by_hash(file_hash: str):
    """Get emails that contain an attachment with the specified file hash."""
    engine = get_correlation_engine()
    return engine.get_emails_by_hash(file_hash)


@router.get("/traverse/{start_node_id}", response_model=dict)
def traverse_graph(
    start_node_id: str,
    max_depth: int = 3,
    max_nodes_per_level: int = 10
):
    """Perform a bounded breadth-first traversal of the correlation graph."""
    engine = get_correlation_engine()
    return engine.traverse_graph(start_node_id, max_depth, max_nodes_per_level)


@router.get("/path/{source_node_id}/{target_node_id}", response_model=dict)
def find_shortest_path(
    source_node_id: str,
    target_node_id: str,
    max_depth: int = 5
):
    """Find the shortest path between two nodes in the correlation graph."""
    engine = get_correlation_engine()
    return engine.find_shortest_path(source_node_id, target_node_id, max_depth)


@router.get("/timeline/{ioc_type}/{ioc_value:path}", response_model=dict)
def get_ioc_timeline(ioc_type: str, ioc_value: str):
    """Get timeline information for a specific IOC."""
    engine = get_correlation_engine()
    return engine.get_ioc_timeline(ioc_value, ioc_type)


@router.get("/trending/{ioc_type}", response_model=list)
def get_trending_iocs(
    ioc_type: str,
    limit: int = 10,
    days_back: int = 7
):
    """Get trending IOCs based on recent activity."""
    engine = get_correlation_engine()
    return engine.get_trending_iocs(ioc_type, limit, days_back)


@router.get("/temporal-correlation/{ioc1_type}/{ioc1_value:path}/{ioc2_type}/{ioc2_value:path}", response_model=dict)
def get_temporal_ioc_correlation(
    ioc1_type: str,
    ioc1_value: str,
    ioc2_type: str,
    ioc2_value: str,
    time_window_hours: int = 24
):
    """Calculate temporal correlation between two IOCs based on co-occurrence within time windows."""
    engine = get_correlation_engine()
    return engine.get_temporal_ioc_correlation(ioc1_type, ioc1_value, ioc2_type, ioc2_value, time_window_hours)


@router.get("/lifetime-stats/{ioc_type}", response_model=dict)
def get_ioc_lifetime_statistics(ioc_type: str):
    """Get lifetime statistics for a specific IOC type across the population."""
    engine = get_correlation_engine()
    return engine.get_ioc_lifetime_statistics(ioc_type)


@router.get("/detect-campaigns", response_model=list)
def detect_campaigns(
    request: Request,
    time_window_days: int = 7,
    min_ioc_count: int = 3,
    min_email_count: int = 2,
    _: None = Depends(rate_limit_dependency)
):
    """Detect potential threat campaigns based on temporal clustering and shared infrastructure."""
    engine = get_correlation_engine()
    return engine.detect_campaigns(time_window_days, min_ioc_count, min_email_count)


@router.post("/threat-hunt", response_model=dict)
def threat_hunt(
    request: Request,
    query: ThreatHuntQuery,
    db: Session = Depends(get_db),
    _: None = Depends(rate_limit_dependency)
):
    """
    Execute a structured threat hunt query.

    Allows complex querying of the correlation graph using a structured model
    that includes IOCs, time windows, email filters, and other constraints.
    """
    engine = get_correlation_engine()

    # Start with all emails in the graph
    from .. import models
    email_query = db.query(models.GraphNode).filter(
        models.GraphNode.node_type == "EMAIL"
    )

    # Apply time window constraints
    if query.time_window:
        from datetime import datetime, timedelta
        cutoff_time = datetime.utcnow()

        if query.time_window.hours:
            cutoff_time = cutoff_time - timedelta(hours=query.time_window.hours)
        elif query.time_window.days:
            cutoff_time = cutoff_time - timedelta(days=query.time_window.days)

        if query.time_window.start_time:
            try:
                start_time = datetime.fromisoformat(query.time_window.start_time)
                cutoff_time = max(cutoff_time, start_time)
            except ValueError:
                pass

        if query.time_window.end_time:
            try:
                end_time = datetime.fromisoformat(query.time_window.end_time)
                cutoff_time = min(cutoff_time, end_time)
            except ValueError:
                pass

        email_query = email_query.filter(models.GraphNode.last_seen >= cutoff_time)

    # Apply email filters
    if query.email_filters:
        if query.email_filters.sender_domain:
            # Filter emails by sender domain
            email_query = email_query.join(
                models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
            ).join(
                models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
            ).filter(
                models.GraphEdge.relationship_type == "SENT_FROM",
                models.GraphNode.node_type == "SENDER",
                models.GraphNode.display_value.contains(query.email_filters.sender_domain)
            )

        if query.email_filters.subject_contains:
            # Filter emails by subject text
            email_query = email_query.filter(
                models.GraphNode.subject.contains(query.email_filters.subject_contains)
            )

        if query.email_filters.has_attachment is not None:
            # Filter by attachment presence
            if query.email_filters.has_attachment:
                email_query = email_query.join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.relationship_type == "HAS_ATTACHMENT"
                ).subquery()
            else:
                # Emails without attachments
                attachment_subquery = db.query(models.GraphNode.node_id).join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.relationship_type == "HAS_ATTACHMENT"
                ).subquery()
                email_query = email_query.filter(~models.GraphNode.node_id.in_(attachment_subquery))

        if query.email_filters.has_url is not None:
            # Filter by URL presence
            if query.email_filters.has_url:
                email_query = email_query.join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.relationship_type == "CONTAINS_URL"
                ).subquery()
            else:
                # Emails without URLs
                url_subquery = db.query(models.GraphNode.node_id).join(
                    models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                ).filter(
                    models.GraphEdge.relationship_type == "CONTAINS_URL"
                ).subquery()
                email_query = email_query.filter(~models.GraphNode.node_id.in_(url_subquery))

    # Apply IOC constraints
    if query.iocs:
        # For each IOC, find emails that contain it
        ioc_email_sets = []
        for ioc_query in query.iocs:
            ioc_value = ioc_query.value
            ioc_type = ioc_query.type.upper()

            # Find the IOC node
            ioc_node = db.query(models.GraphNode).filter(
                models.GraphNode.node_type == ioc_type,
                models.GraphNode.canonical_value == ioc_value
            ).first()

            if ioc_node:
                # Find emails that contain this IOC
                if ioc_type == "IP":
                    email_subquery = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc_node.node_id,
                        models.GraphEdge.relationship_type == "RECEIVED_FROM_IP",
                        models.GraphNode.node_type == "EMAIL"
                    ).subquery()
                elif ioc_type == "DOMAIN":
                    email_subquery = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).join(
                        models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                    ).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).join(
                        models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                    ).filter(
                        models.GraphEdge.relationship_type == "SENT_FROM",
                        models.GraphNode.node_type == "SENDER",
                        models.GraphEdge.relationship_type == "USES_DOMAIN",
                        models.GraphNode.node_type == "DOMAIN",
                        models.GraphNode.node_id == ioc_node.node_id,
                        models.GraphNode.node_type == "EMAIL"
                    ).subquery()
                elif ioc_type == "URL":
                    email_subquery = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).filter(
                        models.GraphEdge.target_node_id == ioc_node.node_id,
                        models.GraphEdge.relationship_type == "CONTAINS_URL",
                        models.GraphNode.node_type == "EMAIL"
                    ).subquery()
                elif ioc_type == "FILE_HASH":
                    email_subquery = db.query(models.GraphNode).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).join(
                        models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                    ).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).join(
                        models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                    ).join(
                        models.GraphEdge, models.GraphNode.node_id == models.GraphEdge.source_node_id
                    ).join(
                        models.GraphNode, models.GraphEdge.target_node_id == models.GraphNode.node_id
                    ).filter(
                        models.GraphEdge.relationship_type == "HAS_ATTACHMENT",
                        models.GraphNode.node_type == "ATTACHMENT",
                        models.GraphEdge.relationship_type == "HAS_FILE_HASH",
                        models.GraphNode.node_type == "FILE_HASH",
                        models.GraphNode.node_id == ioc_node.node_id,
                        models.GraphNode.node_type == "EMAIL"
                    ).subquery()
                else:
                    # Unsupported IOC type
                    continue

                ioc_email_sets.append(email_subquery)

        # Intersect all IOC email sets (emails that contain ALL specified IOCs)
        if ioc_email_sets:
            from sqlalchemy import intersect
            intersection_query = ioc_email_sets[0]
            for email_set in ioc_email_sets[1:]:
                intersection_query = intersect(intersection_query, email_set)
            email_query = email_query.filter(models.GraphNode.node_id.in_(intersection_query))

    # Apply correlation inclusion
    if not query.include_correlated:
        # Exclude emails that are only correlated (not primary)
        # This is a simplified approach - in reality we'd need to check edge types
        pass

    # Limit results
    email_query = email_query.limit(query.max_results)

    # Execute query
    emails = email_query.all()

    # Format results
    results = []
    for email_node in emails:
        results.append({
            "email_id": email_node.node_id,
            "subject": getattr(email_node, 'subject', ''),
            "sender": getattr(email_node, 'sender', ''),
            "first_seen": email_node.first_seen.isoformat() if email_node.first_seen else None,
            "last_seen": email_node.last_seen.isoformat() if email_node.last_seen else None,
            "timestamp": email_node.last_seen.isoformat() if email_node.last_seen else None
        })

    response = {
        "query": query.dict(),
        "results_count": len(results),
        "emails": results,
        "hunt_id": f"hunt_{int(datetime.utcnow().timestamp())}"
    }

    # Include campaigns if requested
    if query.include_campaigns:
        campaigns = engine.detect_campaigns(
            time_window_days=7,
            min_ioc_count=2,
            min_email_count=2
        )
        response["campaigns"] = campaigns

    return response


class ProviderInfo(BaseModel):
    provider_id: str
    provider_name: str
    provider_type: Optional[str] = None
    reliability_score: float = 0.5


@router.post("/threat-intel/provider", response_model=dict)
def add_threat_intelligence_provider(
    provider: ProviderInfo,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Add or update a threat intelligence provider.
    """
    engine = get_correlation_engine()
    node_id = engine.add_threat_intelligence_provider(
        provider_id=provider.provider_id,
        provider_name=provider.provider_name,
        provider_type=provider.provider_type,
        reliability_score=provider.reliability_score
    )
    return {
        "provider_id": node_id,
        "status": "success"
    }


class IocLink(BaseModel):
    ioc_type: str
    ioc_value: str
    provider_id: str
    confidence: float = 0.8
    description: Optional[str] = None


@router.post("/threat-intel/link", response_model=dict)
def link_ioc_to_provider(
    link: IocLink,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Link an IOC to a threat intelligence provider.
    """
    engine = get_correlation_engine()
    success = engine.link_ioc_to_provider(
        ioc_type=link.ioc_type,
        ioc_value=link.ioc_value,
        provider_id=link.provider_id,
        confidence=link.confidence,
        description=link.description
    )

    if success:
        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "provider_id": provider_id,
            "status": "linked"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to link IOC to provider"
        )


@router.get("/threat-intel/reputation/{ioc_type}/{ioc_value:path}", response_model=dict)
def get_ioc_reputation(
    ioc_type: str,
    ioc_value: str,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Get reputation score for an IOC based on threat intelligence provider reports.
    """
    engine = get_correlation_engine()
    reputation = engine.get_ioc_reputation(
        ioc_type=ioc_type,
        ioc_value=ioc_value
    )
    return reputation


@router.get("/threat-intel/correlate/{ioc_type}/{ioc_value:path}", response_model=dict)
def correlate_with_threat_intelligence(
    ioc_type: str,
    ioc_value: str,
    time_window_days: int = 30,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Correlate an IOC with threat intelligence provider activity over time.
    """
    engine = get_correlation_engine()
    correlation = engine.correlate_with_threat_intelligence(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        time_window_days=time_window_days
    )
    return correlation


# Case Management Integration Models
class CaseAssociation(BaseModel):
    node_id: str
    case_id: int


class EdgeCaseAssociation(BaseModel):
    source_node_id: str
    target_node_id: str
    relationship_type: str
    case_id: int


# Case Management Integration Endpoints
@router.post("/case/associate-node", response_model=dict)
def associate_node_with_case(
    association: CaseAssociation,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Associate a graph node with a case.
    """
    engine = get_correlation_engine()
    success = engine.associate_node_with_case(
        node_id=association.node_id,
        case_id=association.case_id
    )

    if success:
        return {
            "node_id": association.node_id,
            "case_id": association.case_id,
            "status": "associated"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to associate node with case"
        )


@router.post("/case/associate-edge", response_model=dict)
def associate_edge_with_case(
    association: EdgeCaseAssociation,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Associate a graph edge with a case.
    """
    engine = get_correlation_engine()
    success = engine.associate_edge_with_case(
        source_node_id=association.source_node_id,
        target_node_id=association.target_node_id,
        relationship_type=association.relationship_type,
        case_id=association.case_id
    )

    if success:
        return {
            "source_node_id": association.source_node_id,
            "target_node_id": association.target_node_id,
            "relationship_type": association.relationship_type,
            "case_id": association.case_id,
            "status": "associated"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to associate edge with case"
        )


@router.get("/case/{case_id}/subgraph", response_model=dict)
def get_case_subgraph(
    case_id: int,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Get a subgraph containing only nodes and edges associated with a specific case.
    """
    engine = get_correlation_engine()
    subgraph = engine.get_case_subgraph(case_id)

    if "error" in subgraph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=subgraph["error"]
        )

    return subgraph


# Export endpoints
@router.get("/export/json")
def export_graph_json(
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Export the full correlation graph in JSON format (Cytoscape.js).
    """
    engine = get_correlation_engine()
    graph = engine.build_cytoscape_graph()
    return graph


@router.get("/export/json/{case_id}")
def export_case_graph_json(
    case_id: int,
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Export a case subgraph in JSON format (Cytoscape.js).
    """
    engine = get_correlation_engine()
    subgraph = engine.get_case_subgraph(case_id)

    if "error" in subgraph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=subgraph["error"]
        )

    # Return just the elements part for clean Cytoscape JSON
    return subgraph.get("elements", {"nodes": [], "edges": []})


@router.get("/export/png")
def export_graph_png(
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Export the full correlation graph in PNG format.
    Note: PNG export requires additional dependencies and is not implemented in this version.
    Returns JSON format as fallback.
    """
    # For now, return JSON as PNG export would require additional libraries like cairosvg
    engine = get_correlation_engine()
    graph = engine.build_cytoscape_graph()
    return {
        "format": "json_fallback",
        "message": "PNG export not implemented; returning JSON format. Install required dependencies for PNG export.",
        "data": graph
    }


@router.get("/export/svg")
def export_graph_svg(
    request: Request = None,
    _: None = Depends(rate_limit_dependency)
):
    """
    Export the full correlation graph in SVG format.
    Note: SVG export requires additional dependencies and is not implemented in this version.
    Returns JSON format as fallback.
    """
    # For now, return JSON as SVG export would require additional libraries
    engine = get_correlation_engine()
    graph = engine.build_cytoscape_graph()
    return {
        "format": "json_fallback",
        "message": "SVG export not implemented; returning JSON format. Install required dependencies for SVG export.",
        "data": graph
    }