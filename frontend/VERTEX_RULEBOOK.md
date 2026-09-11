# VERTEX — Working Rulebook

This document is the operating contract for future VERTEX work. It records the rules and preferences established during the project conversation. The newest explicit user instruction overrides an older one.

## 1. Core priority: correctness first

1. Working correctly is more important than having an impressive frontend.
2. Do not optimize for visual polish until the underlying interaction, routing, API calls, states, and data handling work correctly.
3. After each meaningful change, check it before moving on.
4. Even small changes must be checked. Do not batch many unverified changes together and hope the final build works.
5. Before delivering a package, revisit the checklist and verify every completed item again.
6. Never claim a build, deployment, live API test, or browser test was performed unless it actually was.
7. When an environment prevents a test, mark it as unverified and explain exactly what could not be tested.

## 2. Mandatory development loop

For every task/change:

1. Understand the current implementation.
2. Identify the exact backend/API/data contract involved.
3. Decide the smallest safe implementation.
4. Make the change.
5. Run the relevant check immediately.
6. Inspect the result for regressions.
7. Continue only after the step passes.
8. At the end, run the full available verification pass.
9. Revisit the checklist one more time and mark each item accurately.

A useful mental loop is:

`Understand → Change → Run → Inspect → Fix → Re-run → Checklist review`

## 3. Backend-first rule

The backend is the source of truth for frontend behavior.

Before implementing or redesigning a screen:

- Inspect the backend router(s).
- Inspect the response schemas/models.
- Inspect existing frontend API wrappers and how the old UI consumed them.
- Confirm field names, types, units, optional values, pagination, errors, and endpoint methods.
- Use real backend response shapes. Never invent fields for convenience.

Examples already discovered in VERTEX:

- Email list summaries do not contain a risk score.
- Evidence verification returns `entry_count`, `errors`, and `valid`; it does not return an `entries` array.
- Shared infrastructure is returned under `{ shared: ... }`.
- Audit log responses do not include a `previous_hash` field.
- Full-analysis `overall_risk_score` is a 0–1 value, while the risk endpoint's `score` is 0–100.

The frontend must reflect the backend, not the other way around.

## 4. No fake functionality

- Do not create fake metrics just to make a dashboard look complete.
- Do not display fields that the backend does not provide.
- Do not silently make hundreds of extra API requests to simulate missing data.
- Do not claim a visualization is live if it is based on static/example data.
- Do not use placeholder data in production-facing states unless it is clearly identified as placeholder content.

## 5. Feature-control rule

Do not add product features automatically.

If a useful new feature is identified during implementation:

1. Stop before implementing it.
2. Describe the feature clearly.
3. Explain why it would help.
4. Ask the user for confirmation.
5. Implement it only after explicit approval.

A UI improvement that preserves existing behavior is allowed within an approved UI-polish scope. A new user capability is not.

## 6. Phase 2 hold

The planned Phase 2 feature is explicitly deferred:

**Live analysis progress via WebSocket/SSE** — expose forensic/risk-analysis progress in real time instead of waiting for the full analysis request to finish.

Do not implement Phase 2 unless the user explicitly asks to resume it.

## 7. Current frontend technology contract

The VERTEX frontend direction is:

- Next.js
- TypeScript + TSX
- App Router
- Tailwind CSS
- Motion for UI animation
- Lucide React for icons
- Axios for the existing API integration
- Vercel-compatible build/deployment

Do not silently revert the frontend to Vite or plain JavaScript.

## 8. UI quality direction

The current approved visual direction is:

- Rounded edges are preferred. This supersedes the earlier request for sharp edges.
- Light mode and dark mode are required.
- The product should feel like a polished consumer/product interface, closer in usability and density to Instagram/YouTube than a generic AI-generated dashboard.
- Avoid excessive rounded cards, giant empty panels, huge gradients, unnecessary glassmorphism, and decorative noise.
- Avoid the visual look of an obviously AI-generated dashboard.
- Use hierarchy, spacing, typography, and interaction states deliberately.
- Visualizations are preferred over long blocks of plain numeric text when data can be communicated more clearly with a chart/graph.
- Animation should communicate state, navigation, loading, or interaction; it should not exist merely for decoration.
- Responsive behavior is required.

## 9. Existing-functionality preservation

When replacing the frontend:

- Preserve existing routes unless explicitly approved otherwise.
- Preserve existing API endpoints and methods.
- Preserve existing forensic workflow semantics.
- Preserve report export, evidence verification, cases, correlation, audit, and analysis functionality.
- Do not modify backend behavior during a frontend-only task.
- Do not remove a working control just because it is visually inconvenient; redesign it instead.

## 10. Production-safety rule

Prefer isolated work:

- Original repository/production code must remain safe.
- Work in a copy/feature branch or a downloadable ZIP unless the user explicitly authorizes direct repository changes.
- Never force-push or overwrite production code as part of ordinary frontend work.
- Keep changes reviewable and reversible.

## 11. Deployment verification rule

The deployment environment matters.

For Vercel:

- The frontend should be detected as Next.js.
- The correct root directory must be configured.
- The build command must match the actual framework (`npm run build`).
- Environment variable names must match the Next.js client-side convention (`NEXT_PUBLIC_API_URL`).
- Never leave stale Vite build configuration in place after migration.

If Vercel produces an error:

1. Read the actual build log.
2. Identify the first meaningful error.
3. Fix that error only after understanding why it occurred.
4. Re-run the build.
5. Re-check the rest of the build log for secondary errors.

## 12. Live backend/UI verification

The user explicitly wants the UI checked against the real backend.

When possible:

1. Start/use the deployed backend.
2. Verify `/health`.
3. Verify the relevant API endpoints.
4. Open the frontend against the deployed backend.
5. Test the main user path manually.
6. Check browser console/network errors.
7. Check loading, success, empty, and error states.

The backend currently allows broad CORS, so do not assume CORS is the problem without evidence. Verify the actual request/error.

## 13. Checklist rule

Every substantial task gets a checklist.

The checklist must contain:

- Requested changes.
- Backend/API contract checks.
- Build/type checks.
- Runtime/manual checks.
- Visual checks.
- Regression checks.
- Explicitly deferred items.

At the end:

1. Mark every item as PASS, FAIL, or UNVERIFIED.
2. Re-read the entire checklist.
3. Check each item against the implementation again.
4. Only then report completion.

A checklist is not proof by itself. Each PASS must correspond to an actual check.

## 14. Failure-handling rule

If a test fails:

- Do not move on as though it passed.
- Do not hide the failure behind a visual workaround.
- Find the root cause.
- Fix the smallest correct thing.
- Re-run the failed check.
- Re-run the surrounding checks that could have been affected.

For example, the Vercel CSS failure caused by an invalid escaped Tailwind selector must be treated as a build failure, not ignored because the rest of the UI looks correct.

## 15. Communication rule

Be explicit about:

- What was changed.
- What was checked.
- What actually passed.
- What remains unverified.
- What is intentionally deferred.

Do not use confident language to imply a test happened when it did not.

## 16. Current Phase 1 target

Phase 1 is frontend-focused and includes:

- Functional Next.js + TSX migration.
- Correct backend integration.
- Responsive shell/navigation.
- Light/dark themes.
- Rounded modern visual system.
- Upload experience.
- Email feed/search/sorting/presentation.
- Investigation visualizations and forensic detail presentation.
- Cases UI.
- Correlation graph visualization.
- Audit timeline/verification UI.
- Loading/error/empty/success states.
- Vercel-compatible deployment configuration.

Phase 2 remains deferred.

## 17. Final rule

**Do not stop at “the code looks right.” Run it. Inspect it. Then run it again after the final changes. Finally revisit the checklist.**
