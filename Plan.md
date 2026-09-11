# SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

**Theme:** Blockchain & Cybersecurity
**Organization:** All India Council for Technical Education (AICTE)
**Prize:** ₹1,00,000 INR
**Deadline:** 20 September 2026
**Portal:** sih.gov.in

---

## Background

Email remains one of the most widely used communication channels in government, education, banking, and enterprise ecosystems — and one of the most exploited attack vectors for phishing, impersonation, business email compromise (BEC), financial fraud, credential theft, and malware delivery. Attackers increasingly use spoofed domains, deceptive sender identities, AI-generated language, domain lookalikes, display-name spoofing, hidden redirection links, and relay chains to evade detection.

Traditional email security controls (spam filters, static blacklists, rule-based signatures) are often insufficient. Even when a suspicious email is flagged, organizations often lack the technical capability to trace the source path, identify probable sender infrastructure, correlate geolocation clues, and support investigation into the origin of the email.

## Problem Statement

Existing email security tools focus on filtering/blocking but provide limited intelligence for deep forensic tracing of fraudulent email origins. They don't adequately correlate:
- Email headers
- SMTP relay paths
- SPF/DKIM/DMARC validation results
- IP reputation & geolocation indicators
- Domain registration intelligence
- Behavioral patterns

There's a need for an AI-powered platform that detects phishing/spoofed/impersonated/fraudulent emails in real time, analyzes the full technical structure of an email, traces its transmission path, estimates origin location, and generates forensic intelligence to support investigation — all while respecting legal, privacy, and evidentiary standards.

## Proposed Solution

Build a platform combining NLP, ML, email header forensics, IP intelligence, domain analysis, and graph-based correlation to:
- Ingest raw email content, metadata, and headers
- Validate sender authentication mechanisms
- Extract indicators of compromise
- Reconstruct relay paths
- Analyze originating IPs and geolocation
- Generate a confidence-based fraud risk & probable-origin assessment
- Provide alerts, visual trace maps, and forensic reports

## Key Components (from the official PS)

1. **Fraudulent Email Detection Engine** — NLP analysis of subject/body/urgency cues, phishing indicator detection, AI/ML classification (legitimate / suspicious / impersonated / phishing / fraud), BEC pattern detection (payment diversion, fake invoices, credential harvesting).
2. **Email Header and Protocol Analysis Module** — Deep header analysis (Return-Path, Received, Message-ID, Reply-To, DKIM, SPF, DMARC), anomaly detection in routing/spoofed fields, validation of authorized vs. suspicious relay paths.
3. **Origin Traceability and Location Analysis** — Extraction of originating IPs from header chains, IP geolocation, correlation with VPN/TOR/botnet/cloud-hosting indicators, WHOIS/DNS/MX domain intelligence.
4. **Identity Correlation and Attribution Support** — Correlating indicators with threat intel/blacklists/prior incidents, graph-based relationship analysis between domains/IPs/aliases, confidence-based attribution.
5. **Alerting, Dashboard, and Forensic Reporting** — Real-time alerts, analyst dashboard (fraud score, spoofing indicators, trace path, geolocation map), structured forensic reports, case management for grouping related emails into campaigns.
6. **Privacy, Legal, and Compliance Safeguards** — Controlled handling of personal data, evidence preservation / chain-of-custody, configurable retention & masking.

## Expected Outcomes

- Early, accurate detection of fraudulent/spoofed/phishing emails
- Improved ability to trace origin paths and identify probable source infrastructure
- Enhanced fraud investigation via geolocation + domain intelligence + attribution support
- Reduced financial loss, reputational damage, and data disclosure from email fraud
- Better institutional readiness for incident response and enforcement coordination

---

## Topics need to be learnt



### 1. Email Fraud Detection (ML/NLP core)
- Email header structure basics: `Return-Path`, `Received` chain, `Message-ID`, `Reply-To`
- SPF, DKIM, DMARC — what each validates, how to check alignment programmatically
  - Python: `dkimpy`, `pyspf`, or manual header parsing
- Basic NLP phishing classification
  - Start simple: TF-IDF + scikit-learn classifier (Logistic Regression / Random Forest)
  - Stretch: fine-tune a small transformer (e.g., DistilBERT) if time allows
- URL/domain lookalike detection — Levenshtein distance is enough for a first pass
- Suspicious link/attachment extraction from email body

### 2. Header Forensics & Origin Tracing
- Parsing `Received:` header chains to reconstruct relay path
  - Trickiest part: headers are prepended by each hop (read bottom-to-top), and forged headers are common — build in sanity checks
- IP geolocation — **MaxMind GeoLite2** (free, offline-capable, avoids API rate limits during your demo)

### 3. Domain / Threat Intelligence
- WHOIS lookups: `python-whois`
- DNS / MX record checks: `dnspython`
- Free threat intel feeds/blacklists for enrichment: PhishTank, AbuseIPDB (both have free tiers) — don't build this from scratch

### 4. Dashboard & System Design
- Backend to ingest `.eml` files or connect to a test inbox via IMAP
- Graph visualization for sender/domain/IP correlation — D3.js, or NetworkX + a simple frontend
- Basic case management — a DB schema is enough (Postgres or SQLite)

---

## Suggested Build Priority

1. Header parsing + SPF/DKIM/DMARC validation
2. Basic ML phishing/fraud classifier
3. IP geolocation + relay path visualization
4. Dashboard tying it together (fraud score, trace map, alerts)
5. *(Stretch)* WHOIS/domain intel enrichment, threat intel correlation, graph-based attribution, case management

---

*Compiled from the Smart India Hackathon 2026 Master Catalogue (PS26106).*
