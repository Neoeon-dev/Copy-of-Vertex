# VERTEX Frontend — Next.js Production UI

This frontend replaces the previous Vite UI with a Vercel-friendly Next.js App Router application.

## Stack
- Next.js 16
- React 19
- Tailwind CSS 4
- Motion for React (the current package formerly known as Framer Motion)
- Lucide React
- Axios

## Local development

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

## Vercel

Set the Vercel project's **Root Directory** to the folder containing this `package.json` (for the original VERTEX layout, this is `frontend`). Vercel should then auto-detect Next.js and run `next build`.

Set `NEXT_PUBLIC_API_URL` to the deployed FastAPI API base URL.

## Scope

This is Phase 1 only: production UI/UX modernization and frontend structure cleanup. Existing backend endpoints and forensic workflows are preserved. Live analysis streaming (WebSocket/SSE) is intentionally not included yet.
