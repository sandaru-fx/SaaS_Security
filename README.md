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
| `GET /docs` | No | Swagger UI |

## Frontend Routes

| Route | Access | Description |
|---|---|---|
| `/` | Public | Landing page |
| `/sign-in` | Public | Clerk sign in |
| `/sign-up` | Public | Clerk sign up |
| `/dashboard` | Protected | User dashboard |
| `/profile` | Protected | Profile settings |
| `/projects` | Protected | Project list |
| `/projects/new` | Protected | Create project |
| `/projects/[id]` | Protected | Project details + start audit |
| `/projects/[id]/scans/[scanId]` | Protected | Scan results |

## Development Phases

| Phase | Focus | Status |
|---|---|---|
| 01 | Foundation | ✅ Done |
| 02 | Auth & Users | ✅ Done |
| 03 | Projects & Repo | ✅ Done |
| 04 | Scan Engine | ✅ Done |
| 05 | Report & Score | Pending |
| 06 | AI Layer | Pending |
| 07 | Extended Scans | Pending |
| 08 | Dashboard | Pending |
| 09 | Monetization | Pending |
| 10 | Enterprise | Pending |

## Git Branching

- `main` — production-ready code
- `dev` — active development

## License

Private — All rights reserved.
