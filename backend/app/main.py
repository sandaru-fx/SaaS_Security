from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import billing, dashboard, health, projects, scans, users
from app.config import get_settings
from app.database import Base, engine
from app.db_migrate import run_additive_migrations
from app.models import issue as issue_model  # noqa: F401
from app.models import project as project_model  # noqa: F401
from app.models import scan as scan_model  # noqa: F401
from app.models import user as user_model  # noqa: F401

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await run_additive_migrations(conn)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI Software Auditor Platform API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(billing.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(scans.router, prefix="/api")


@app.get("/")
async def root() -> dict:
    return {
        "message": "AI Software Auditor API",
        "docs": "/docs",
        "health": "/api/health",
        "auth": "/api/users/me",
        "projects": "/api/projects",
        "scans": "/api/scans",
        "dashboard": "/api/dashboard",
    }
