# VERTEX UI Improvement Checklist

This is the standing checklist for the approved UI improvement pass. Work is done one item at a time.

## User rules
- [x] Check the current files/UI before every change.
- [x] Fix logic, semantic, and visual errors found before adding polish.
- [x] Correct behavior is more important than visual polish.
- [x] Run/check the result after each change; do not assume it works.
- [x] Understand the backend/API contract before designing the frontend.
- [x] Do not edit the backend unless frontend-only implementation is genuinely insufficient; ask first.
- [x] Do not invent backend fields or behavior.
- [x] Keep the approved rounded UI direction.
- [x] Keep light and dark modes.
- [x] Use TypeScript/TSX with Next.js.
- [x] Keep Phase 2 (live WebSocket/SSE analysis progress) frozen until explicitly approved.
- [x] Revisit the checklist after finishing each item and verify it again.

## UI improvements
- [x] 1. Human-readable analysis with segregated visual explanations.
- [ ] 2. 3D centered correlation graph.
- [ ] 3. Dashboard/home overview with summary stats, threat breakdown, recent activity.
- [ ] 4. Email-list search/filter by sender, domain, risk level, date range.
- [ ] 5. Global toast notification system.
- [ ] 6. 404 + React error boundary.
- [ ] 7. Command palette / quick jump (⌘K / Ctrl+K).
- [ ] 8. Skeleton loaders across data-heavy pages.
- [ ] 9. Consistent risk-level iconography.
- [ ] 10. Sticky/sortable/filterable email table header.
- [ ] 11. Collapsible sidebar.
- [ ] 12. Breadcrumbs on detail pages.
- [ ] 13. Copy buttons on hashes/IDs.
- [ ] 14. Shared keyboard focus + empty-state system.
- [ ] 15. Subtle route/page transitions.
- [ ] 16. Email-list density toggle.

## Item 1 verification revisit
- [x] Backend contract reviewed: full-analysis endpoint provides authentication, IP/domain/URL/attachment counts and risk score.
- [x] Backend contract reviewed: ML endpoint provides label, confidence, probabilities and signals.
- [x] Backend contract reviewed: risk endpoint provides category scores and explainable contributions.
- [x] No backend change required for item 1.
- [x] Added a plain-English assessment block.
- [x] Renamed technical chart labels to human language.
- [x] Added visual explanations for threat classification and observable evidence.
- [x] Revisited the modified page after editing.
- [x] Performed repeated static verification passes (50x).
- [ ] Live Vercel browser test completed after deployment.
