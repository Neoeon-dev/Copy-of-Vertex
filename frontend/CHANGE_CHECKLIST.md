# VERTEX — Change Verification Checklist

Use this checklist for every meaningful frontend change.

## A. Scope
- [ ] Is this change explicitly requested or already approved?
- [ ] Did a new product feature sneak in? If yes, stop and request confirmation.
- [ ] Is Phase 2 still untouched unless explicitly resumed?

## B. Backend contract
- [ ] Did I inspect the relevant backend router?
- [ ] Did I inspect the relevant response schema/model?
- [ ] Are HTTP method, path, query/body parameters correct?
- [ ] Are response field names and types correct?
- [ ] Did I avoid invented fields and fake data?
- [ ] Did I avoid unnecessary API calls?

## C. Implementation
- [ ] Is the change implemented in the correct Next.js/TSX layer?
- [ ] Are loading/error/empty/success states handled?
- [ ] Are mobile/responsive states handled?
- [ ] Are light and dark themes handled where relevant?
- [ ] Did I preserve existing routes and working behavior?

## D. Immediate verification
- [ ] Did I run the smallest relevant test/check immediately after the change?
- [ ] Did it actually pass?
- [ ] If it failed, did I fix the root cause before continuing?

## E. Final verification
- [ ] TypeScript check passed.
- [ ] Production build passed.
- [ ] ZIP/archive integrity passed, if a ZIP was produced.
- [ ] Main routes were checked.
- [ ] Main API flows were checked.
- [ ] Browser/runtime behavior was checked when available.
- [ ] Console/network errors were checked when browser access was available.
- [ ] Final visual review was completed.

## F. Revisit
- [ ] Re-read this checklist from the beginning.
- [ ] Verify each PASS against an actual observation.
- [ ] Mark anything not actually verified as UNVERIFIED.
- [ ] Record known limitations before reporting completion.

## UI Improvement #1 — Human-readable analysis
- Checked existing investigation page and backend contracts before modifying.
- Frontend-only change; no backend modification required.
- Added plain-English summary and three human-readable insight cards.
- Renamed technical labels such as model probabilities and forensic indicator volume.
- Added human labels for risk categories and classifier output.
- Added human-readable forensic evidence labels (public sending IPs, links found, etc.).
- Revisited the modified file after the change.
- Repeated static verification 50 times.

### Final revisit after the 50-pass check
- PASS: Human-readable assessment present.
- PASS: Human category labels present.
- PASS: Human classifier wording present.
- PASS: Forensic indicator visualization uses plain-English labels.
- PASS: No backend changes were made.
- PASS: No invalid escaped dark-mode hover selector remains.
- PASS: TypeScript/TSX syntax transpilation succeeded for all project source files in all 50 verification passes.
- PASS: Internal relative import paths resolved in all 50 verification passes.
- PASS: Item 2 and later checklist items remain intentionally pending.
- NOTE: A full Next.js production build was not possible in this environment because npm dependency installation timed out.
