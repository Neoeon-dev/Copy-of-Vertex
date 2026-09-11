# VERTEX Frontend — Phase 1

Next.js + TypeScript + Tailwind CSS + Motion + Lucide React frontend for the VERTEX forensic email platform.

## Run

```bash
npm install
npm run dev
```

Set the API base URL in `.env.local`:

```bash
NEXT_PUBLIC_API_URL=https://vertex-8ko3.onrender.com
```

## Vercel

Set **Root Directory** to `frontend` and let Vercel use the Next.js framework with:

```text
npm run build
```

## Scope

This package is Phase 1 only. It contains UI/UX improvements and backend-contract-aligned frontend integration. The planned live-analysis WebSocket/SSE feature is intentionally not included.
