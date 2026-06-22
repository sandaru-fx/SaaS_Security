import asyncio
import logging
import sys
from contextlib import asynccontextmanager

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import billing, dashboard, enterprise, health, projects, scans, users, v1
from app.config import get_settings
from app.database import Base, engine
from app.db_migrate import run_additive_migrations
from app.db_sync import get_sync_session
from app.models import enterprise as enterprise_model  # noqa: F401
from app.models import issue as issue_model  # noqa: F401
from app.models import project as project_model  # noqa: F401
from app.models import scan as scan_model  # noqa: F401
from app.models import user as user_model  # noqa: F401
from app.services.schedule_service import process_due_schedules

settings = get_settings()
logger = logging.getLogger(__name__)


async def _schedule_worker() -> None:
    while True:
        await asyncio.sleep(300)
        session = get_sync_session()
        try:
            count = process_due_schedules(session)
            if count:
                logger.info("Started %d scheduled audit(s)", count)
        except Exception as exc:
            logger.warning("Schedule worker error: %s", exc)
        finally:
            session.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.is_sqlite:
        from pathlib import Path

        Path("data").mkdir(exist_ok=True)

    logger.info("Connecting to database...")
    try:
        async with asyncio.timeout(30):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await run_additive_migrations(conn)
    except TimeoutError as exc:
        logger.error(
            "Database connection timed out. Check DATABASE_URL and that your Neon project is active."
        )
        raise RuntimeError("Database connection timed out") from exc
    logger.info("Database ready")
    schedule_task = asyncio.create_task(_schedule_worker())
    yield
    schedule_task.cancel()


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
app.include_router(enterprise.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(v1.router, prefix="/api")


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
        "enterprise": "/api/enterprise",
        "api_v1": "/api/v1",
    }
