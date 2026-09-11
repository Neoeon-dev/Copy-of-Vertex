# VERTEX Frontend — Phase 1 rebuild

This frontend is intentionally aligned to the current FastAPI backend in `Neoeon-dev/VERTEX`.

## Stack
- Next.js 16 (App Router)
- TypeScript / TSX
- React 19
- Tailwind CSS 4
- Motion
- Lucide React
- Axios

## Backend contract implemented
- `/api/emails` upload, list, detail
- `/api/emails/{id}/authentication`
- `/api/emails/{id}/analyze-full`
- `/api/emails/{id}/classify`
- `/api/emails/{id}/risk`
- `/api/cases` + case email linking
- `/api/audit` + audit verification
- `/api/evidence/verify/{id}`
- `/api/graph` + shared infrastructure
- `/api/graph/email/{id}`
- `/api/reports/{id}/pdf`
- `/health`

## Vercel
Set the Vercel **Root Directory** to the folder containing this `package.json`.
Set:

`NEXT_PUBLIC_API_URL=https://vertex-8ko3.onrender.com`

Do not use `vite build`. Build command is:

`npm run build`

Phase 2 (SSE/WebSocket live analysis progress) is intentionally not included.

## Verification note
The source was statically syntax-checked in this environment. A full Next.js production build requires the npm dependencies to be installed in a network-enabled environment.
