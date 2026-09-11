# MailTrace — Frontend Application

Modern cyber-forensics web application built with **React 19**, **Vite**, **Tailwind CSS v4**, and **Axios**.

## Architecture & Features

The MailTrace frontend communicates with the FastAPI backend through a unified REST API client (`src/api.js`) and Vite / Nginx reverse proxy:

1. **Email Upload (`/`)**:
   - Drag-and-drop `.eml` upload area with immediate MIME type validation.
   - Client-side size guard (10 MB cap).
   - SHA-256 evidence hash calculation display.
   - Auto-navigation to the analyzed dossier on completion.

2. **Analyzed Emails Dossier (`/emails`)**:
   - Sortable index of all analyzed emails with timestamp, sender, subject, and raw SHA-256 evidence fingerprint.
   - Deep links into the detailed investigation view.

3. **Detailed Forensic Analysis (`/emails/:id`)**:
   - Multi-signal risk assessment gauge (0–100) with classification badge (LOW, MEDIUM, HIGH, CRITICAL).
   - One-click **Full Analysis Trigger** running SPF, DKIM, DMARC, Received chain reconstruction, IP/GeoIP intelligence, lookalike domain detection, URL inspection, attachment threat scanning, and ML classification.
   - **Export Forensic Report**: Generates and downloads official investigation report (PDF/HTML format).
   - **Verify Evidence Chain**: Cryptographically validates the append-only SHA-256 evidence chain to guarantee evidence integrity.
   - **Add to Graph**: Links email entities to the threat correlation matrix.
   - Collapsible raw email headers and structured body inspection.

4. **Investigation Cases (`/cases`)**:
   - Case dossier management allowing investigators to group suspicious emails by incident or campaign.
   - Link analyzed emails directly to cases.

5. **Threat Correlation & Campaign Graph (`/graph`)**:
   - Entity relationship graph correlating emails, senders, domains, IP addresses, and cases.
   - Coordinated campaign detector highlighting shared infrastructure (shared malicious IPs, domains, or attachments across different emails).
   - Entity filtering by type (Email, IP, Domain, Sender, Case).

6. **Audit & Evidence Ledger (`/audit`)**:
   - Immutable tamper-evident audit ledger tracking all upload, analysis, and verification events.
   - One-click **Verify Hash Chain Integrity** button executing real-time cryptographic audit verification.

## Development & Build

### Prerequisites
- Node.js 20+
- npm 10+

### Local Development
```bash
# Install dependencies
npm install

# Start Vite dev server on http://localhost:5173
npm run dev

# Run ESLint validation
npm run lint

# Build production bundle into dist/
npm run build
```

### Docker Deployment
The frontend is containerized using a multi-stage build:
1. `node:20-alpine` builds the static production assets.
2. `nginx:alpine` serves the application on port 80 (mapped to port 3000 in `docker-compose.yml`) and reverse-proxies `/api/` and `/health` requests to `backend:8000`.
