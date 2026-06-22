import redis.asyncio as aioredis
from fastapi import APIRouter
from sqlalchemy import text

from app.config import get_settings
from app.database import engine

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health")
async def health_check() -> dict:
    """Basic liveness check."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "features": {
            "local_project_paths": settings.local_paths_enabled,
        },
    }


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Check connectivity to PostgreSQL and Redis."""
    checks: dict[str, str] = {
        "api": "healthy",
        "database": "unknown",
        "redis": "unknown",
    }

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as exc:
        checks["database"] = f"unhealthy: {exc.__class__.__name__}"

    try:
        client = aioredis.from_url(settings.redis_url)
        try:
            pong = await client.ping()
            checks["redis"] = "healthy" if pong else "unhealthy"
        finally:
            await client.aclose()
    except Exception as exc:
        checks["redis"] = f"unhealthy: {exc.__class__.__name__}"

    all_healthy = all(value == "healthy" for value in checks.values())
    return {
        "status": "ready" if all_healthy else "degraded",
        "checks": checks,
    }
