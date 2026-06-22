import logging
import threading
from uuid import UUID

from celery import Celery
from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.services import subscription_service
from app.services.scan_runner import execute_scan

logger = logging.getLogger(__name__)
settings = get_settings()


async def create_scan(
    db: AsyncSession,
    user: User,
    project: Project,
) -> Scan:
    if project.status != "ready":
        raise ValueError("Project must be in 'ready' status before scanning")

    if project.source_type == "website" and not project.domain_verified:
        raise ValueError(
            "Domain ownership must be verified before scanning this website. "
            "Complete verification on the project page."
        )

    allowed, message = subscription_service.can_start_scan(user)
    if not allowed:
        raise ValueError(message)

    scan = Scan(
        project_id=project.id,
        user_id=user.id,
        status="queued",
    )
    db.add(scan)
    subscription_service.record_scan_usage(user)
    await db.commit()
    await db.refresh(scan)
    return scan


async def list_project_scans(
    db: AsyncSession,
    user_id: UUID,
    project_id: UUID,
) -> tuple[list[Scan], int]:
    result = await db.execute(
        select(Scan)
        .where(Scan.project_id == project_id, Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
    )
    scans = list(result.scalars().all())
    return scans, len(scans)


async def get_scan(
    db: AsyncSession,
    user_id: UUID,
    scan_id: UUID,
) -> Scan | None:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    return result.scalar_one_or_none()


def dispatch_scan(scan_id: str, background_tasks: BackgroundTasks | None = None) -> str:
    """Queue scan via Celery, or run in-process if Redis is unavailable."""
    try:
        celery_app = Celery("auditor_worker", broker=settings.celery_broker_url)
        celery_app.send_task("tasks.run_audit", args=[scan_id])
        return "celery"
    except Exception as exc:
        logger.warning("Celery dispatch failed, using fallback: %s", exc)

    if background_tasks is not None:
        background_tasks.add_task(execute_scan, scan_id)
        return "background"

    threading.Thread(target=execute_scan, args=(scan_id,), daemon=True).start()
    return "thread"
