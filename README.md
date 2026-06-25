# AI Software Auditor Platform

> Problem → Impact → Business Risk → Fix → Priority

Monorepo for the AI Software Auditor SaaS platform (Plan 0).

## Project Structure

```
SaaS_2/
├── frontend/          # Next.js + TypeScript + Tailwind + Clerk
├── backend/           # FastAPI API server + JWT auth
├── workers/           # Celery background scan workers
├── docker-compose.yml # PostgreSQL + Redis + Backend + Worker
├── .env.example       # Environment template
└── README.md
```

## Completed Phases

### Phase 1 — Foundation
- [x] Monorepo structure
- [x] Next.js frontend
- [x] FastAPI backend with health endpoints
- [x] Celery worker skeleton
- [x] Docker Compose (PostgreSQL, Redis, Backend, Worker)

### Phase 2 — Auth & Users
- [x] Clerk signup / login / logout
- [x] Protected routes (dashboard, profile)
- [x] Backend JWT verification
- [x] User table sync (`GET /api/users/me`)
- [x] Profile page with update (`PATCH /api/users/me`)

### Phase 3 — Projects & Repo
- [x] Project CRUD (create, list, view, update, delete)
- [x] GitHub public repo connect (clone via API)
- [x] ZIP file upload with safe extraction
- [x] Project dashboard UI
- [x] Local file storage with auto cleanup on delete

### Phase 4 — Scan Engine
- [x] Security pattern scanner
- [x] Secrets detection scanner
- [x] Dependency vulnerability scan (OSV API)
- [x] Semgrep integration (when installed)
- [x] Celery worker + background fallback
- [x] Scan & Issue database tables
- [x] Scan results UI with severity filters

### Phase 5 — Report & Health Score
- [x] Health score algorithm (0–100) with grade
- [x] Category breakdown (Security, Architecture, Performance, Quality, DevOps)
- [x] Executive summary generation
- [x] Priority-ordered fix plan
- [x] Production-ready assessment
- [x] Professional audit report UI with score ring
- [x] Issue detail modal (Problem → Impact → Fix)

### Phase 6 — AI Auditor Layer
- [x] AI-generated executive summary & business risk narrative
- [x] Per-issue business risk in Problem → Impact → Business Risk → Fix → Priority format
- [x] Strategic recommendations
- [x] OpenAI integration with intelligent rule-based fallback (works offline)
- [x] Auto-migration for new columns (no Alembic needed)
- [x] AI Auditor Assessment section in the report UI

### Phase 7 — Architecture & Extended Scans
- [x] Architecture heuristics (large files, deep folders, layering, circular deps)
- [x] Performance patterns (N+1 queries, unbounded fetch, blocking in async)
- [x] Code quality checks (TODO debt, long functions, debug statements)
- [x] DevOps hygiene (.env in repo, CI/CD, Docker, .gitignore)
- [x] All 5 audit categories now populated by dedicated scanners
- [x] Extended category filters in scan results UI

### Phase 8 — Dashboard, History & Trends
- [x] Dashboard API with stats, recent scans, score trend, category averages
- [x] Score trend chart (SVG) on main dashboard
- [x] Recent audits list across all projects
- [x] Active scan notifications (in-app banner + completion alert)
- [x] Scan history with health scores on project page
- [x] Compare scans — before vs after with score and category deltas
- [x] Project settings — rename and update description

### Phase 9 — Monetization & Pro Features
- [x] Subscription plans (Free / Pro / Team) with usage limits
- [x] Free plan: 8 audits/month, 100MB uploads; Pro/Team: unlimited + higher caps
- [x] Stripe checkout, billing portal, and webhook integration
- [x] PDF audit report export (Pro feature)
- [x] AI Deep Audit gated to Pro/Team plans
- [x] Landing page with pricing section
- [x] Billing page with plan management and usage meter

## Stripe Setup (Phase 9)

1. Create products/prices in [Stripe Dashboard](https://dashboard.stripe.com)
2. Add to root `.env`:
   ```env
   STRIPE_SECRET_KEY=sk_test_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   STRIPE_PRICE_PRO=price_...
   STRIPE_PRICE_TEAM=price_...
   FRONTEND_URL=http://localhost:3000
   ```
3. Forward webhooks locally: `stripe listen --forward-to localhost:8000/api/billing/webhook`
4. Without Stripe keys the app runs on the Free plan — no payments required for development.

### Phase 10 — Enterprise & Scale
- [x] Team organizations and member invites
- [x] API keys + REST v1 (`/api/v1/projects/{id}/scans`)
- [x] Scheduled audits (weekly/monthly background worker)
- [x] Custom regex rules scanner
- [x] Project webhooks on audit completion (CI/CD integration)
- [x] Email alerts for critical issues (SMTP optional)
- [x] False positive management — dismiss issues
- [x] Enterprise settings UI + GitHub Actions workflow example

### Phase 11 — Advanced App Security
- [x] API/OpenAPI security scanner
- [x] Infrastructure-as-Code (Terraform, CloudFormation) scanning
- [x] Git history secrets scan
- [x] Bandit, crypto weakness, reachability analysis

### Phase 12 — Risk Scoring & Prioritization
- [x] EPSS + KEV exploit signals
- [x] Weighted 0–100 risk scores per issue
- [x] Top Fix Now panel and sorted issue list

### Phase 13 — GraphQL & WebSocket Security
- [x] GraphQL static analysis (introspection, depth, batching)
- [x] WebSocket security patterns

### Phase 14 — Browser DAST
- [x] Playwright-based browser DAST for authenticated flows

### Phase 15 — Cloud CSPM
- [x] AWS, Azure, and GCP misconfiguration scanners

### Phase 16 — Supply Chain Security
- [x] Typosquatting, Sigstore/SLSA signals, malicious package checks

### Phase 17 — AI/LLM Security
- [x] Prompt injection, LangChain risks, OWASP LLM Top 10 patterns

### Phase 18 — Auto-Fix PRs
- [x] Safe deterministic GitHub remediation pull requests

### Phase 19 — OWASP ZAP DAST
- [x] Optional ZAP baseline integration for website scans

### Phase 20 — Teams & CI Integration
- [x] Organization UI, member limits
- [x] GitHub PR status checks on audit completion

### Phase 21 — Launch Readiness
- [x] S3-compatible upload storage (optional `STORAGE_BACKEND=s3`)
- [x] First-login onboarding wizard
- [x] Slack audit-completion alerts (Profile → Notifications)
- [x] GitHub Actions CI (backend tests + frontend build)
- [x] Sentry error tracking (optional `SENTRY_DSN`)
- [x] Production deploy guide (`DEPLOY.md`)

## Production Deploy

See **[DEPLOY.md](./DEPLOY.md)** for Render + Vercel + Neon + S3 setup.

## Stripe Setup (Phase 9)

The AI Auditor turns raw findings into executive-friendly narratives.

- **With an OpenAI key** (`OPENAI_API_KEY` in `.env`): summaries are generated by the model (`OPENAI_MODEL`, default `gpt-4o-mini`).
- **Without a key**: a built-in rule-based auditor produces professional narratives automatically — no external calls, fully offline.

The provider used is shown in the report ("AI-powered" vs "Rule-based").

## Prerequisites

- **Node.js** 18+
- **Python** 3.12+
- **Docker Desktop** (optional — for PostgreSQL & Redis locally)
- **Clerk account** (free) — https://dashboard.clerk.com

## Clerk Setup (Required for Phase 2)

1. Create a new application at [Clerk Dashboard](https://dashboard.clerk.com)
2. Copy your API keys
3. Update root `.env`:
   ```env
   NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
   CLERK_SECRET_KEY=sk_test_...
   CLERK_JWKS_URL=https://YOUR-APP.clerk.accounts.dev/.well-known/jwks.json
   CLERK_JWT_ISSUER=https://YOUR-APP.clerk.accounts.dev
   ```
4. Copy frontend env:
   ```bash
   copy frontend\.env.local.example frontend\.env.local
   ```
   Paste your `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY` into `frontend\.env.local`

> JWKS URL and Issuer are found in Clerk Dashboard → **API Keys** → **Advanced** → JWT template section, or derive from your Clerk frontend API URL.

## Quick Start

### Option A — With Docker (recommended)

1. Copy environment files:
   ```bash
   copy .env.example .env
   copy frontend\.env.local.example frontend\.env.local
   ```
   Fill in Clerk keys in both files.

2. Start infrastructure + backend + worker:
   ```bash
   docker compose up -d
   ```

3. Start frontend:
   ```bash
   cd frontend
   npm run dev
   ```

4. Open:
   - Frontend: http://localhost:3000
   - Sign up: http://localhost:3000/sign-up
   - Dashboard: http://localhost:3000/dashboard
   - API docs: http://localhost:8000/docs

### Option B — Without Docker

1. Copy env files and add Clerk keys (see above)

2. Setup Python:
   ```bash
   npm run setup
   ```

3. Start backend:
   ```bash
   cd backend
   venv\Scripts\activate
   uvicorn app.main:app --reload --port 8000
   ```

4. Start frontend:
   ```bash
   cd frontend
   npm run dev
   ```

> Without Docker, user sync to PostgreSQL requires a running database. `/api/health/ready` will show DB as unhealthy until Docker is started.

## API Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /api/health` | No | Liveness check |
| `GET /api/health/ready` | No | Readiness (DB + Redis) |
| `GET /api/users/me` | Yes | Get/sync current user |
| `PATCH /api/users/me` | Yes | Update profile |
| `GET /api/projects` | Yes | List user projects |
| `POST /api/projects/github` | Yes | Create from GitHub URL |
| `POST /api/projects/upload` | Yes | Create from ZIP upload |
| `GET /api/projects/{id}` | Yes | Get project details |
| `PATCH /api/projects/{id}` | Yes | Update project |
| `DELETE /api/projects/{id}` | Yes | Delete project + files |
| `POST /api/projects/{id}/scans` | Yes | Start security audit |
| `GET /api/projects/{id}/scans` | Yes | List project scans |
| `GET /api/scans/{id}` | Yes | Get scan status |
| `GET /api/scans/{id}/issues` | Yes | List scan issues |
| `GET /api/scans/{id}/report` | Yes | Full audit report + health score |
| `GET /docs` | No | Swagger UI |

## Frontend Routes

| Route | Access | Description |
|---|---|---|
| `/` | Public | Landing page |
| `/sign-in` | Public | Clerk sign in |
| `/sign-up` | Public | Clerk sign up |
| `/dashboard` | Protected | User dashboard |
| `/profile` | Protected | Profile + Slack/email notifications |
| `/projects` | Protected | Project list |
| `/projects/new` | Protected | Create project |
| `/projects/[id]` | Protected | Project details + start audit |
| `/projects/[id]/scans/[scanId]` | Protected | Scan results |

## Development Phases

| Phase | Focus | Status |
|---|---|---|
| 01–05 | Foundation → Reports | ✅ Done |
| 06–10 | AI, Extended Scans, Dashboard, Billing, Enterprise | ✅ Done |
| 11–15 | API/IaC, Risk Scoring, GraphQL/WS, Browser DAST, CSPM | ✅ Done |
| 16–20 | Supply Chain, LLM, Auto-Fix, ZAP, Teams/CI | ✅ Done |
| 21 | Launch readiness (S3, onboarding, Slack, CI, deploy) | ✅ Done |

## Git Branching

- `main` — production-ready code
- `dev` — active development

## License

Private — All rights reserved.
