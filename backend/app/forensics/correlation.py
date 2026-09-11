"""Correlation graph engine using NetworkX.

Builds a graph of relationships between emails, senders, domains, IPs,
URLs, and cases. The graph allows multiple analyzed emails to reveal
shared infrastructure and campaigns.

Node types: Email, Sender, Domain, IP, ASN, URL, Case, Campaign
Edge types: SENT_FROM, ROUTED_THROUGH, RESOLVES_TO, HOSTED_BY,
            LINKS_TO, RELATED_TO, IMPERSONATES, PART_OF_CAMPAIGN
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # email | sender | domain | ip | asn | url | case | campaign
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": {
                "id": self.id,
                "label": self.label,
                "nodeType": self.node_type,
                **self.properties,
            }
        }


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    edge_type: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": {
                "id": self.id,
                "source": self.source,
                "target": self.target,
                "edgeType": self.edge_type,
                **self.properties,
            }
        }


@dataclass
class CorrelationGraph:
    """Complete correlation graph for display with Cytoscape.js."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "elements": {
                "nodes": [n.to_dict() for n in self.nodes],
                "edges": [e.to_dict() for e in self.edges],
            },
            "stats": self.stats,
        }


class CorrelationEngine:
    """Builds and queries the correlation graph across multiple emails."""

    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._node_counter = 0
        self._edge_counter = 0

    def _next_node_id(self, prefix: str) -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter}"

    def _next_edge_id(self) -> str:
        self._edge_counter += 1
        return f"e_{self._edge_counter}"

    def add_email(self, email_data: dict[str, Any]) -> None:
        """Add an email and all its relationships to the graph."""
        email_id = email_data.get("id")
        sender = email_data.get("sender")
        subject = email_data.get("subject", "")
        case_id = email_data.get("case_id")

        # Email node
        email_node_id = f"email_{email_id}"
        self._graph.add_node(
            email_node_id,
            label=subject[:40] or f"Email #{email_id}",
            node_type="email",
            email_id=email_id,
        )

        # Sender node
        if sender:
            sender_domain = sender.split("@")[-1] if "@" in sender else sender
            sender_node_id = f"sender_{sender}"
            self._graph.add_node(
                sender_node_id,
                label=sender,
                node_type="sender",
                email_address=sender,
            )
            self._add_edge(email_node_id, sender_node_id, "SENT_FROM")

            # Domain node
            domain_node_id = f"domain_{sender_domain}"
            self._graph.add_node(
                domain_node_id,
                label=sender_domain,
                node_type="domain",
            )
            self._add_edge(sender_node_id, domain_node_id, "BELONGS_TO")

        # Case node
        if case_id:
            case_node_id = f"case_{case_id}"
            self._graph.add_node(
                case_node_id,
                label=f"Case #{case_id}",
                node_type="case",
            )
            self._add_edge(email_node_id, case_node_id, "PART_OF_CASE")

    def add_ips(self, email_id: int, ip_analyses: list[dict[str, Any]]) -> None:
        """Add IP relationships for an email."""
        email_node_id = f"email_{email_id}"

        for ip_data in ip_analyses:
            ip = ip_data.get("ip", "")
            if not ip:
                continue

            ip_node_id = f"ip_{ip}"
            self._graph.add_node(
                ip_node_id,
                label=ip,
                node_type="ip",
                is_public=ip_data.get("is_public"),
            )
            self._add_edge(email_node_id, ip_node_id, "ROUTED_THROUGH")

            # ASN node
            asn = ip_data.get("asn", {})
            if asn and asn.get("asn"):
                asn_node_id = f"asn_{asn['asn']}"
                self._graph.add_node(
                    asn_node_id,
                    label=f"AS{asn['asn']}",
                    node_type="asn",
                    organization=asn.get("organization"),
                )
                self._add_edge(ip_node_id, asn_node_id, "HOSTED_BY")

    def add_urls(self, email_id: int, url_analyses: list[dict[str, Any]]) -> None:
        """Add URL relationships for an email."""
        email_node_id = f"email_{email_id}"

        for url_data in url_analyses:
            url = url_data.get("url", "")
            if not url:
                continue

            url_node_id = f"url_{hash(url) & 0xFFFFFFFF:08x}"
            self._graph.add_node(
                url_node_id,
                label=url[:60],
                node_type="url",
                full_url=url,
            )
            self._add_edge(email_node_id, url_node_id, "LINKS_TO")

    def add_domains(self, email_id: int, domain_analyses: list[dict[str, Any]]) -> None:
        """Add domain intelligence relationships."""
        email_node_id = f"email_{email_id}"

        for da in domain_analyses:
            domain = da.get("domain", "")
            if not domain:
                continue

            domain_node_id = f"domain_{domain}"
            self._graph.add_node(
                domain_node_id,
                label=domain,
                node_type="domain",
                risk_score=da.get("risk_score", 0),
            )

            # Lookalike relationships
            for lookalike in da.get("lookalikes", []):
                brand = lookalike.get("brand_domain", "")
                if brand:
                    brand_node_id = f"domain_{brand}"
                    self._graph.add_node(
                        brand_node_id,
                        label=brand,
                        node_type="domain",
                        is_brand=True,
                    )
                    self._add_edge(domain_node_id, brand_node_id, "IMPERSONATES")

    def add_case(self, case_id: int, title: str, email_ids: list[int]) -> None:
        """Add a case and link all its emails."""
        case_node_id = f"case_{case_id}"
        self._graph.add_node(
            case_node_id,
            label=title or f"Case #{case_id}",
            node_type="case",
        )
        for eid in email_ids:
            email_node_id = f"email_{eid}"
            if self._graph.has_node(email_node_id):
                self._add_edge(email_node_id, case_node_id, "PART_OF_CASE")

    def _add_edge(self, source: str, target: str, edge_type: str) -> None:
        """Add an edge if it doesn't already exist."""
        if not self._graph.has_edge(source, target):
            edge_id = self._next_edge_id()
            self._graph.add_edge(source, target, edge_type=edge_type, edge_id=edge_id)

    def build_cytoscape_graph(self) -> CorrelationGraph:
        """Convert the NetworkX graph to Cytoscape.js format."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        for node_id, data in self._graph.nodes(data=True):
            nodes.append(GraphNode(
                id=node_id,
                label=data.get("label", node_id),
                node_type=data.get("node_type", "unknown"),
                properties={k: v for k, v in data.items() if k not in ("label", "node_type")},
            ))

        for source, target, data in self._graph.edges(data=True):
            edges.append(GraphEdge(
                id=data.get("edge_id", f"e_{source}_{target}"),
                source=source,
                target=target,
                edge_type=data.get("edge_type", "RELATED_TO"),
            ))

        # Compute stats
        node_types = {}
        for n in nodes:
            node_types[n.node_type] = node_types.get(n.node_type, 0) + 1

        edge_types = {}
        for e in edges:
            edge_types[e.edge_type] = edge_types.get(e.edge_type, 0) + 1

        stats = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": node_types,
            "edge_types": edge_types,
        }

        return CorrelationGraph(nodes=nodes, edges=edges, stats=stats)

    def get_shared_infrastructure(self) -> list[dict[str, Any]]:
        """Find IPs or domains shared by multiple emails."""
        shared: list[dict[str, Any]] = []

        # Find IP nodes connected to multiple email nodes
        for node_id, data in self._graph.nodes(data=True):
            if data.get("node_type") == "ip":
                email_neighbors = [
                    n for n in self._graph.predecessors(node_id)
                    if self._graph.nodes[n].get("node_type") == "email"
                ]
                if len(email_neighbors) > 1:
                    shared.append({
                        "type": "shared_ip",
                        "value": data.get("label"),
                        "email_count": len(email_neighbors),
                        "email_ids": [
                            self._graph.nodes[n].get("email_id")
                            for n in email_neighbors
                        ],
                    })

            elif data.get("node_type") == "domain":
                email_neighbors = [
                    n for n in self._graph.predecessors(node_id)
                    if self._graph.nodes[n].get("node_type") == "email"
                ]
                if len(email_neighbors) > 1:
                    shared.append({
                        "type": "shared_domain",
                        "value": data.get("label"),
                        "email_count": len(email_neighbors),
                        "email_ids": [
                            self._graph.nodes[n].get("email_id")
                            for n in email_neighbors
                        ],
                    })

        return shared


# Singleton
_engine: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine
