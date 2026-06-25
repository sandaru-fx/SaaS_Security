# Production Deployment Guide

Deploy the AI Software Auditor to **Vercel (frontend)** + **Render (backend)** + **Neon (PostgreSQL)**.

## Architecture

```
Users → Vercel (Next.js) → Render (FastAPI) → Neon PostgreSQL
                              ↓
                         Upstash Redis (Celery)
                              ↓
                         AWS S3 (uploads, optional)
```

## 1. Database — Neon

1. Create a project at [neon.tech](https://neon.tech)
2. Copy the **pooled** connection string (`postgresql://...`)
3. Use it as `DATABASE_URL` on Render (the backend normalizes it to `postgresql+psycopg://`)

## 2. Redis — Upstash (recommended)

1. Create a Redis database at [upstash.com](https://upstash.com)
2. Set on Render:
   - `REDIS_URL`
   - `CELERY_BROKER_URL` (same value)

Without Redis, scans still run via in-process fallback but scheduled audits and Celery workers won't scale.

## 3. Backend — Render

1. Connect repo `sandaru-fx/SaaS_Security`, branch `main`, root `backend`
2. Use the included `render.yaml` blueprint or create a **Docker** web service
3. Required environment variables:

| Variable | Example |
|----------|---------|
| `ENVIRONMENT` | `production` |
| `DATABASE_URL` | Neon connection string |
| `REDIS_URL` | `rediss://...` |
| `CELERY_BROKER_URL` | same as Redis |
| `SECRET_KEY` | random 32+ chars |
| `CORS_ORIGINS` | `https://your-app.vercel.app` |
| `FRONTEND_URL` | `https://your-app.vercel.app` |
| `CLERK_SECRET_KEY` | from Clerk dashboard |
| `CLERK_JWKS_URL` | `https://xxx.clerk.accounts.dev/.well-known/jwks.json` |
| `CLERK_JWT_ISSUER` | `https://xxx.clerk.accounts.dev` |

### Optional — uploads on S3 (recommended for production)

Render free tier disk is ephemeral. Use S3 so uploads survive restarts:

```env
STORAGE_BACKEND=s3
S3_BUCKET=your-auditor-uploads
S3_REGION=ap-southeast-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

### Optional — billing, AI, alerts

```env
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_TEAM=price_...
GEMINI_API_KEY=...
OPENAI_API_KEY=...
SMTP_HOST=...
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM_EMAIL=auditor@yourdomain.com
SENTRY_DSN=https://...@sentry.io/...
```

### Stripe webhook

Point Stripe to: `https://your-api.onrender.com/api/billing/webhook`

## 4. Frontend — Vercel

1. Import repo, set **Root Directory** to `frontend`
2. Environment variables (see `frontend/vercel.env.example`):

```env
NEXT_PUBLIC_API_URL=https://your-api.onrender.com
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_SECRET_KEY=sk_live_...
```

3. Deploy

## 5. Clerk

1. Add your Vercel domain under **Domains**
2. Set redirect URLs: `/dashboard`, `/sign-in`, `/sign-up`
3. Copy JWKS URL and issuer to backend env

## 6. Health checks

- Liveness: `GET /api/health`
- Readiness: `GET /api/health/ready` (DB + Redis)

## 7. Local development

```bash
copy .env.example .env
copy frontend\.env.local.example frontend\.env.local
docker compose up -d
cd frontend && npm run dev
cd backend && venv\Scripts\python.exe run.py --reload
```

## 8. Post-deploy checklist

- [ ] Sign up on production URL
- [ ] Create folder/ZIP project and run audit
- [ ] Verify billing page loads (`/billing`)
- [ ] Test Stripe checkout (test mode first)
- [ ] Configure S3 if using uploads
- [ ] Add Slack webhook in Profile → Notifications (optional)

## Git branches

- `main` — production deploys
- `dev` — active development, merge to main for release
