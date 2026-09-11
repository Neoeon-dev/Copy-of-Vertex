# Vercel setup

Project settings:

- Framework: Next.js
- Root Directory: `frontend`
- Build Command: `npm run build`
- Production API: `https://vertex-8ko3.onrender.com`

`NEXT_PUBLIC_API_URL` may be set in Vercel for overrides. The app also has the production Render URL as a safe fallback, so a missing Vercel variable does not accidentally point a production browser at `localhost`.
