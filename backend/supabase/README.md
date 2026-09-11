# MailTrace — Supabase Deployment

This directory contains Supabase deployment preparation for MailTrace.

## Why This Folder Exists

MailTrace is designed to work with any PostgreSQL database. Supabase provides
a hosted PostgreSQL service with additional features like:
- Connection pooling (PgBouncer)
- Built-in authentication
- RESTful API auto-generation
- Real-time subscriptions
- Dashboard for database management

This folder prepares the project for eventual Supabase deployment.

## Architecture

### Local Development
```
Frontend (React/Vite)
        ↓
FastAPI Backend
        ↓
PostgreSQL (Docker or local)
```

### Deployment Target
```
Frontend (Vercel/Netlify)
        ↓
FastAPI Backend (Railway/Fly.io)
        ↓
Supabase PostgreSQL (hosted)
```

**Important:** MailTrace keeps the FastAPI backend. Supabase serves as the
hosted PostgreSQL database — we do NOT rewrite the backend into Supabase
Edge Functions.

## Required Supabase Project Configuration

1. Create a Supabase project at https://supabase.com
2. Note your project URL and keys
3. Ensure PostgreSQL 15+ is available
4. Enable the required extensions if needed

## Database Setup

MailTrace uses SQLAlchemy with `create_all()` for schema creation. When
connecting to Supabase PostgreSQL, the schema is created automatically on
first startup.

### Connection Settings

Use the Supabase connection string in your `.env`:

```bash
DATABASE_URL=postgresql+psycopg2://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
```

**Important:** Use the **Pooler** connection (port 6543) for transaction mode,
or the **Direct** connection (port 5432) for session mode.

### Environment Variables

```bash
DATABASE_URL=postgresql+psycopg2://...  # Supabase connection string
DEMO_MODE=false                          # Disable demo mode in production
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key  # NEVER expose to frontend
```

## Migration Procedure

1. Set `DATABASE_URL` to your Supabase connection string
2. Start the backend: it will create all tables automatically
3. Verify tables exist in the Supabase dashboard

### Manual Migration (if needed)

```bash
# Connect to Supabase and run schema creation
cd backend
DATABASE_URL="your-supabase-url" python -c "from app.db import init_db; init_db()"
```

## Local PostgreSQL vs Supabase PostgreSQL

| Feature | Local PostgreSQL | Supabase PostgreSQL |
|---------|-----------------|---------------------|
| Connection | localhost:5432 | aws-0-region.pooler.supabase.com:6543 |
| Auth | None | Supabase Auth (optional) |
| Dashboard | pgAdmin/DBeaver | Supabase Dashboard |
| Backups | Manual | Automatic |
| Scaling | Manual | Automatic |
| Free Tier | N/A | 500MB, 50K MAU |

## Security Considerations

- **NEVER** expose `SUPABASE_SERVICE_ROLE_KEY` to the frontend
- Use Row Level Security (RLS) if implementing user authentication
- Use environment variables for all credentials
- Never commit `.env` files to version control

## What Is Already Implemented

- ✅ PostgreSQL-compatible SQLAlchemy models
- ✅ Environment-based configuration
- ✅ Connection pooling with `pool_pre_ping`
- ✅ Proper session management
- ✅ No SQLite dependencies

## What Must Be Done Manually

1. **Create Supabase project** — https://supabase.com
2. **Get connection string** — from Supabase dashboard → Settings → Database
3. **Set environment variables** — in your deployment platform
4. **Configure connection pooling** — choose session vs transaction mode
5. **Set up backups** — configure automatic backups in Supabase
6. **Monitor usage** — check Supabase dashboard for connection/count limits

## Verifying Connectivity

```bash
# Test connection to Supabase
cd backend
DATABASE_URL="your-supabase-url" python -c "
from app.db import engine
from sqlalchemy import text
with engine.connect() as conn:
    result = conn.execute(text('SELECT version()'))
    print(result.fetchone()[0])
"
```

## References

- [Supabase Documentation](https://supabase.com/docs)
- [Supabase PostgreSQL](https://supabase.com/docs/guides/database)
- [Connection Pooling](https://supabase.com/docs/guides/database/connecting-to-postgres#connection-pooling)
