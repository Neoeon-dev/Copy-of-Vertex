# VERTEX Phase 1 UI Checklist

## Approved design direction
- Rounded cards and controls are the default. The earlier "sharp edges" request is superseded.
- Light and dark modes are available and persist in local storage.
- Visual language aims for modern consumer-product polish (Instagram/YouTube-like density and clarity) rather than generic AI dashboard styling.

## UI coverage
- Upload workspace: drag/drop, .eml validation, size validation, upload progress, recent evidence, loading/error/empty states.
- Global shell: responsive sidebar, mobile drawer, sticky header, API health indicator, page transitions, theme toggle.
- Email feed: search, newest/oldest sorting, case assignment filter, evidence cards, responsive states.
- Investigation page: risk gauge, category bars, ML probability chart, indicator-volume chart, SPF/DKIM/DMARC cards, investigation timeline, signal contribution chart, evidence verification, correlation action, export report, metadata, raw headers, body and attachments.
- Cases: case cards, linked counts, dossier modal, linked-email workflow, create-case modal, loading/empty/error states.
- Correlation: visual SVG graph, type filters, search, shared infrastructure, node details, responsive layout.
- Audit: verification action, metrics, chronological timeline, hash copy, loading/empty/error states.

## Backend contract rules
- Email feed does not pretend the list endpoint contains risk scores.
- Evidence verification uses `entry_count` and `errors` from the real endpoint response.
- Shared infrastructure uses the real `{ shared: ... }` response shape.
- Audit UI does not display fields the API does not return.
- Full analysis uses the backend's 0-1 `overall_risk_score`, converted to a display score out of 100.

## Verification
- Archive integrity checked after packaging.
- TypeScript parser/transpiler run completed without syntax/parser errors. Full type/build verification could not run in this environment because frontend dependencies could not be installed before the network/runtime timeout.
