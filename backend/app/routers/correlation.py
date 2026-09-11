"""Correlation graph and forensic report endpoints.

GET  /api/graph                — get full correlation graph
POST /api/graph/email/{id}     — add an email to the graph
GET  /api/graph/shared         — find shared infrastructure
GET  /api/reports/{email_id}/pdf — generate forensic PDF report
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..forensics.correlation import get_correlation_engine
from ..models import Email
from ..utils import escape_html, get_headers_dict

logger = logging.getLogger(__name__)

router = APIRouter(tags=["graph"])


# ── Correlation graph endpoints ──────────────────────────────────────


@router.post("/api/graph/email/{email_id}")
def add_email_to_graph(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Add an email and its analysis to the correlation graph."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    engine = get_correlation_engine()

    # Add email basics
    engine.add_email({
        "id": email.id,
        "subject": email.subject,
        "sender": email.sender,
        "case_id": email.case_id,
    })

    # Add IP intelligence if headers exist
    if email.headers:
        from ..forensics.ip_intelligence import extract_ips_from_headers, analyze_ips
        headers = get_headers_dict(email.headers)

        ips = extract_ips_from_headers(headers)
        ip_analyses = [ia.to_dict() for ia in analyze_ips(ips)]
        engine.add_ips(email_id, ip_analyses)

        # Add domains
        from ..forensics.domain_intel import extract_domains_from_headers, analyze_domain
        domains = extract_domains_from_headers(headers)
        domain_analyses = [analyze_domain(d).to_dict() for d in domains]
        engine.add_domains(email_id, domain_analyses)

    # Add URLs
    from ..forensics.url_analyzer import extract_urls_from_email, analyze_urls
    urls = extract_urls_from_email(body_text=email.body_text, body_html=email.body_html)
    url_analyses = [ua.to_dict() for ua in analyze_urls(urls)]
    engine.add_urls(email_id, url_analyses)

    return {"status": "ok", "email_id": email_id}


@router.get("/api/graph")
def get_graph():
    """Get the full correlation graph in Cytoscape.js format."""
    engine = get_correlation_engine()
    graph = engine.build_cytoscape_graph()
    return graph.to_dict()


@router.get("/api/graph/shared")
def get_shared_infrastructure():
    """Find IPs or domains shared by multiple emails."""
    engine = get_correlation_engine()
    return {"shared": engine.get_shared_infrastructure()}


# ── PDF Report ───────────────────────────────────────────────────────


@router.get("/api/reports/{email_id}/pdf")
def generate_pdf_report(
    email_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    """Generate a forensic PDF report for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    # Build report data
    report_data = _build_report_data(email, db)

    # Generate HTML report
    html = _render_report_html(report_data)

    # Convert to PDF using WeasyPrint
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html).write_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=\"mailtrace-report-{email_id}.pdf\""
            },
        )
    except Exception as e:
        logger.warning("PDF generation failed: %s", e)
        # Return HTML as fallback
        return Response(
            content=html,
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=\"mailtrace-report-{email_id}.html\""
            },
        )


def _build_report_data(email: Email, db: Session) -> dict[str, Any]:
    """Build the data structure for the forensic report."""
    # Run analysis on-the-fly
    from ..forensics.spf_analyzer import analyze_spf
    from ..forensics.dkim_analyzer import analyze_dkim
    from ..forensics.dmarc_analyzer import analyze_dmarc
    from ..forensics.received_analyzer import parse_received_headers
    from ..forensics.ip_intelligence import extract_ips_from_headers, analyze_ips
    from ..forensics.domain_intel import extract_domains_from_headers, analyze_domain
    from ..forensics.url_analyzer import extract_urls_from_email, analyze_urls
    from ..forensics.attachment_analyzer import analyze_attachments
    from ..forensics.risk_engine import get_risk_engine
    from ..ml.classifier import get_classifier

    headers = {}
    for h in email.headers:
        key = h.name.lower()
        if key in headers:
            existing = headers[key]
            if isinstance(existing, list):
                existing.append(h.value)
            else:
                headers[key] = [existing, h.value]
        else:
            headers[key] = h.value

    from_domain = email.sender

    spf = analyze_spf(headers=headers, email_sender_domain=from_domain)
    dkim_results = analyze_dkim(headers=headers, raw_email_bytes=None, email_sender_domain=from_domain)
    dkim_first = dkim_results[0] if dkim_results else None
    spf_envelope = spf.domain if spf.domain != from_domain else None
    dmarc = analyze_dmarc(
        email_sender_domain=from_domain,
        spf_result=spf.result,
        spf_envelope_domain=spf_envelope,
        dkim_result=dkim_first.result if dkim_first else None,
        dkim_domain=dkim_first.domain if dkim_first else None,
    )

    received = parse_received_headers(headers)
    ips = extract_ips_from_headers(headers)
    ip_analyses = [ia.to_dict() for ia in analyze_ips(ips)]
    domains = extract_domains_from_headers(headers)
    domain_analyses = [analyze_domain(d).to_dict() for d in domains]
    urls = extract_urls_from_email(body_text=email.body_text, body_html=email.body_html)
    url_analyses = [ua.to_dict() for ua in analyze_urls(urls)]
    att_dicts = [{"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256} for a in email.attachments]
    att_analyses = [aa.to_dict() for aa in analyze_attachments(att_dicts)]

    classifier = get_classifier()
    ml = classifier.classify(subject=email.subject, sender=email.sender, sender_name=email.sender_name, body_text=email.body_text, body_html=email.body_html)

    engine = get_risk_engine()
    risk = engine.assess(
        ml_label=ml.label, ml_confidence=ml.confidence, ml_risk_score=ml.risk_score,
        ml_signals=ml.signals, ml_signal_details=ml.signal_details,
        spf_result=spf.result, dkim_result=dkim_first.result if dkim_first else None,
        dmarc_result=dmarc.result, sender=email.sender, sender_name=email.sender_name,
        reply_to=email.reply_to, domain_analyses=domain_analyses, url_analyses=url_analyses,
        attachment_analyses=att_analyses, received_anomalies=received.anomalies,
        total_hops=received.total_hops, ip_analyses=ip_analyses,
    )

    return {
        "email_id": email.id,
        "subject": email.subject,
        "sender": email.sender,
        "sender_name": email.sender_name,
        "to": email.to,
        "date": email.date.isoformat() if email.date else None,
        "sha256": email.sha256,
        "size": email.size,
        "created_at": email.created_at.isoformat(),
        "spf": {"result": spf.result, "domain": spf.domain, "details": spf.details},
        "dkim": {"result": dkim_first.result if dkim_first else "NONE", "domain": dkim_first.domain if dkim_first else None, "details": dkim_first.details if dkim_first else None},
        "dmarc": {"result": dmarc.result, "domain": dmarc.domain, "details": dmarc.details},
        "total_hops": received.total_hops,
        "public_ips": received.public_ips,
        "ip_analysis": ip_analyses,
        "domain_analysis": domain_analyses,
        "url_analysis": url_analyses,
        "attachment_analysis": att_analyses,
        "ml_label": ml.label,
        "ml_confidence": ml.confidence,
        "ml_signals": ml.signals,
        "risk_score": risk.score,
        "risk_level": risk.level,
        "risk_summary": risk.summary,
        "risk_limitations": risk.limitations,
        "risk_contributions": [c.to_dict() for c in risk.contributions[:10]],
    }


def _render_report_html(data: dict[str, Any]) -> str:
    """Render the forensic report as HTML."""
    e = escape_html  # shorthand
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MailTrace Forensic Report — Email #{data['email_id']}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1e293b; font-size: 12px; line-height: 1.5; }}
h1 {{ font-size: 22px; border-bottom: 2px solid #6366f1; padding-bottom: 8px; color: #1e293b; }}
h2 {{ font-size: 16px; color: #6366f1; margin-top: 24px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
th, td {{ text-align: left; padding: 6px 10px; border: 1px solid #e2e8f0; font-size: 11px; }}
th {{ background: #f8fafc; font-weight: 600; }}
.pass {{ color: #10b981; font-weight: bold; }}
.fail {{ color: #ef4444; font-weight: bold; }}
.softfail {{ color: #f59e0b; font-weight: bold; }}
.risk-bar {{ height: 8px; border-radius: 4px; background: #e2e8f0; }}
.risk-fill {{ height: 100%; border-radius: 4px; }}
.footer {{ margin-top: 30px; font-size: 10px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 8px; }}
.limitation {{ font-size: 10px; color: #94a3b8; font-style: italic; }}
</style>
</head>
<body>
<h1>MailTrace — Forensic Email Analysis Report</h1>
<p><strong>Email ID:</strong> #{data['email_id']} &nbsp;|&nbsp; <strong>Generated:</strong> {data['created_at']}</p>

<h2>1. Evidence Identity</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>SHA-256</td><td style="font-family: monospace; font-size: 10px;">{data['sha256']}</td></tr>
<tr><td>Filename</td><td>{data.get('filename', 'N/A')}</td></tr>
<tr><td>Size</td><td>{data['size']} bytes</td></tr>
</table>

<h2>2. Email Metadata</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Subject</td><td>{e(data['subject']) or '(none)'}</td></tr>
<tr><td>From</td><td>{e(data['sender']) or '(none)'} ({e(data['sender_name']) or ''})</td></tr>
<tr><td>To</td><td>{e(', '.join(r.get('address', '') for r in (data['to'] or [])))}</td></tr>
<tr><td>Date</td><td>{data['date'] or 'N/A'}</td></tr>
</table>

<h2>3. Risk Assessment</h2>
<div style="display: flex; align-items: center; gap: 16px; margin: 8px 0;">
<div style="font-size: 36px; font-weight: bold;">{data['risk_score']:.0f}</div>
<div>
<div style="font-size: 14px; font-weight: bold;">{data['risk_level']}</div>
<div style="font-size: 11px; color: #64748b;">out of 100</div>
</div>
</div>
<p>{data['risk_summary']}</p>

<h2>4. Authentication Analysis</h2>
<table>
<tr><th>Mechanism</th><th>Result</th><th>Domain</th><th>Details</th></tr>
<tr><td>SPF</td><td class="{data['spf']['result'].lower()}">{data['spf']['result']}</td><td>{e(data['spf']['domain']) or 'N/A'}</td><td>{e(data['spf']['details']) or ''}</td></tr>
<tr><td>DKIM</td><td class="{data['dkim']['result'].lower()}">{data['dkim']['result']}</td><td>{e(data['dkim']['domain']) or 'N/A'}</td><td>{e(data['dkim']['details']) or ''}</td></tr>
<tr><td>DMARC</td><td class="{data['dmarc']['result'].lower()}">{data['dmarc']['result']}</td><td>{e(data['dmarc']['domain']) or 'N/A'}</td><td>{e(data['dmarc']['details']) or ''}</td></tr>
</table>

<h2>5. Received Path ({data['total_hops']} hops)</h2>
<p>Public IPs: {', '.join(data['public_ips']) if data['public_ips'] else 'None'}</p>

<h2>6. ML Classification</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Classification</td><td>{data['ml_label'].upper()}</td></tr>
<tr><td>Confidence</td><td>{data['ml_confidence']:.0%}</td></tr>
</table>

<h2>7. Top Risk Factors</h2>
<table>
<tr><th>Signal</th><th>Description</th><th>Contribution</th></tr>    {''.join(f"<tr><td>{e(c['signal'])}</td><td>{e(c['description'])}</td><td>{c['contribution']:.1f}</td></tr>" for c in data['risk_contributions'] if c['contribution'] > 0)}
</table>

<div class="footer">
<p><strong>MailTrace Forensic Report</strong> — SIH 2026 Email Threat Detection & Forensic Intelligence Platform</p>
<p class="limitation">{''.join(f"<p class='limitation'>• {l}</p>" for l in data['risk_limitations'])}</p>
</div>
</body>
</html>"""
