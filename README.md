# AI Software Auditor Platform

> Problem → Impact → Business Risk → Fix → Priority

Monorepo for the AI Software Auditor SaaS platform (Plan 0).

## Project Structure

```
SaaS_2/
├── frontend/          # Next.js + TypeScript + Tailwind
├── backend/           # FastAPI API server
├── workers/           # Celery background scan workers
├── docker-compose.yml # PostgreSQL + Redis + Backend + Worker
├── .env.example       # Environment template
└── README.md
```

## Phase 1 — Foundation (Current)

- [x] Monorepo structure
- [x] Next.js frontend
- [x] FastAPI backend with health endpoints
- [x] Celery worker skeleton
- [x] Docker Compose (PostgreSQL, Redis, Backend, Worker)
- [x] Environment configuration

## Prerequisites

- **Node.js** 18+ (you have v22)
- **Python** 3.12+ (you have 3.14)
- **Docker Desktop** (optional — for PostgreSQL & Redis locally)

## Quick Start

### Option A — With Docker (recommended)

1. Copy environment file:
   ```bash
   copy .env.example .env
   ```

2. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) if not installed.

3. Start infrastructure + backend + worker:
   ```bash
   docker compose up -d
   ```

4. Start frontend (separate terminal):
   ```bash
   cd frontend
   npm run dev
   ```

5. Open:
   - Frontend: http://localhost:3000
   - API docs: http://localhost:8000/docs
   - Health: http://localhost:8000/api/health

### Option B — Without Docker (frontend + API only)

1. Copy environment file:
   ```bash
   copy .env.example .env
   ```

2. Setup Python environments:
   ```bash
   npm run setup
   ```

3. Start backend:
   ```bash
   cd backend
   venv\Scripts\activate
   uvicorn app.main:app --reload --port 8000
   ```

4. Start frontend (new terminal):
   ```bash
   cd frontend
   npm run dev
   ```

> Without Docker, `/api/health/ready` will show database & Redis as unhealthy — that's expected until you install Docker or run PostgreSQL/Redis manually.

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | API info |
| `GET /api/health` | Liveness check |
| `GET /api/health/ready` | Readiness (DB + Redis) |
| `GET /docs` | Swagger UI |

## Development Phases

| Phase | Focus | Status |
|---|---|---|
| 01 | Foundation | ✅ In progress |
| 02 | Auth & Users | Pending |
| 03 | Projects & Repo | Pending |
| 04 | Scan Engine | Pending |
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
