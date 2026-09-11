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
