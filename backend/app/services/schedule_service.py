"""Scheduled audit execution."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scan import Scan
from app.models.enterprise import ScanSchedule
from app.models.user import User
from app.services.scan_service import dispatch_scan
from app.services.subscription_service import can_start_scan, record_scan_usage

logger = logging.getLogger(__name__)

FREQUENCY_DAYS = {"weekly": 7, "monthly": 30}


def compute_next_run(frequency: str, from_time: datetime | None = None) -> datetime:
    base = from_time or datetime.now(timezone.utc)
    days = FREQUENCY_DAYS.get(frequency, 7)
    return base + timedelta(days=days)


def process_due_schedules(session: Session) -> int:
    """Run all due schedules. Returns count of scans started."""
    now = datetime.now(timezone.utc)
    schedules = session.execute(
        select(ScanSchedule).where(
            ScanSchedule.enabled.is_(True),
            ScanSchedule.next_run_at <= now,
        )
    ).scalars().all()

    started = 0
    for schedule in schedules:
        project = session.get(Project, schedule.project_id)
        user = session.get(User, schedule.user_id)
        if not project or not user or project.status != "ready":
            schedule.next_run_at = compute_next_run(schedule.frequency, now)
            continue

        allowed, _ = can_start_scan(user)
        if not allowed:
            logger.info("Skipping schedule %s — scan limit reached", schedule.id)
            schedule.next_run_at = compute_next_run(schedule.frequency, now)
            continue

        scan = Scan(project_id=project.id, user_id=user.id, status="queued")
        session.add(scan)
        record_scan_usage(user)
        session.commit()
        session.refresh(scan)

        dispatch_scan(str(scan.id), background_tasks=None)
        schedule.last_run_at = now
        schedule.next_run_at = compute_next_run(schedule.frequency, now)
        started += 1

    session.commit()
    return started
