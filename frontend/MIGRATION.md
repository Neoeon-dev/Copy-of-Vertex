# VERTEX frontend migration

## Replace the old frontend

Copy this folder over the existing `frontend/` directory in your copied repository. Keep the backend directory unchanged.

The old Vite entry points (`vite.config.js`, `src/main.jsx`, `src/App.jsx`) are intentionally replaced by the Next.js App Router structure under `src/app`.

## Vercel settings

For the Vercel project:

1. Set **Root Directory** to `frontend`.
2. Remove any manually configured build command such as `vite build`.
3. Let Vercel use the Next.js framework detection, or keep the included `vercel.json` build command: `npm run build`.
4. Add the environment variable `NEXT_PUBLIC_API_URL` with your FastAPI deployment URL.

The build error shown in the screenshot (`vite: command not found`) is expected to disappear because the frontend no longer invokes Vite; Vercel will build the Next.js app instead.

## Phase 1 scope

This release is the UI/UX and frontend architecture pass only. Existing API calls and routes remain. Do not implement live WebSocket/SSE analysis progress in this release; that remains the explicitly deferred Phase 2 feature.
