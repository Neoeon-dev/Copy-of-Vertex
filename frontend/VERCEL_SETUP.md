# Vercel setup

1. Put this frontend in the repository directory Vercel deploys.
2. If the repository keeps `backend/` beside `frontend/`, set **Root Directory** to `frontend` in Vercel.
3. Framework preset: **Next.js**.
4. Build command: `npm run build`.
5. Install command: `npm install`.
6. Environment variable:
   - `NEXT_PUBLIC_API_URL` = `https://vertex-8ko3.onrender.com`
7. Remove any old Vite build command or Vite configuration for the deployed frontend.
