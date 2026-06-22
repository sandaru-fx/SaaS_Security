"""Dashboard aggregation and scan comparison."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models.issue import Issue
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.dashboard import (
    ActiveScanItem,
    CategoryAverage,
    DashboardResponse,
    DashboardStats,
    RecentScanItem,
    RemediationItemResponse,
    ScanCompareResponse,
    TrendPoint,
)
from app.schemas.scan import ScanResponse
from app.services.remediation_service import compare_remediation
from app.services.report_service import AUDIT_CATEGORIES

CATEGORY_FIELDS = {
    "security": "security_score",
    "architecture": "architecture_score",
    "performance": "performance_score",
    "quality": "quality_score",
    "devops": "devops_score",
}


def _to_scan_response(scan: Scan) -> ScanResponse:
    scanners = [s.strip() for s in (scan.scanners_used or "").split(",") if s.strip()]
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        scanners_used=scanners,
        total_issues=scan.total_issues,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        health_score=scan.health_score,
        security_score=scan.security_score,
        architecture_score=scan.architecture_score,
        performance_score=scan.performance_score,
        quality_score=scan.quality_score,
        devops_score=scan.devops_score,
        grade=scan.grade,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
    )


async def _load_user_scans_with_projects(
    db: AsyncSession,
    user_id: UUID,
) -> list[tuple[Scan, Project]]:
    result = await db.execute(
        select(Scan, Project)
        .join(Project, Scan.project_id == Project.id)
        .where(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
    )
    return list(result.all())


async def get_dashboard(db: AsyncSession, user_id: UUID) -> DashboardResponse:
    projects_result = await db.execute(
        select(Project).where(Project.user_id == user_id)
    )
    projects = list(projects_result.scalars().all())
    project_map = {p.id: p for p in projects}

    rows = await _load_user_scans_with_projects(db, user_id)
    scans = [scan for scan, _ in rows]

    completed = [s for s in scans if s.status == "completed" and s.health_score is not None]
    scores = [s.health_score for s in completed if s.health_score is not None]

    score_change = None
    if len(completed) >= 2:
        by_time = sorted(
            completed,
            key=lambda s: s.completed_at or s.created_at,
            reverse=True,
        )
        score_change = (by_time[0].health_score or 0) - (by_time[1].health_score or 0)

    recent_scans: list[RecentScanItem] = []
    for scan, project in rows[:10]:
        recent_scans.append(
            RecentScanItem(
                scan_id=scan.id,
                project_id=project.id,
                project_name=project.name,
                status=scan.status,
                health_score=scan.health_score,
                grade=scan.grade,
                total_issues=scan.total_issues,
                critical_count=scan.critical_count,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
            )
        )

    trend_points: list[TrendPoint] = []
    trend_candidates = sorted(
        completed,
        key=lambda s: s.completed_at or s.created_at,
    )
    for scan in trend_candidates[-30:]:
        project = project_map.get(scan.project_id)
        if not project or scan.health_score is None:
            continue
        trend_points.append(
            TrendPoint(
                scan_id=scan.id,
                project_id=scan.project_id,
                project_name=project.name,
                health_score=scan.health_score,
                grade=scan.grade,
                completed_at=scan.completed_at or scan.created_at,
            )
        )

    category_averages = _category_averages(completed, project_map)
    active_scans = _active_scans(rows)

    stats = DashboardStats(
        total_projects=len(projects),
        ready_projects=sum(1 for p in projects if p.status == "ready"),
        total_scans=len(scans),
        completed_scans=len(completed),
        average_health_score=round(sum(scores) / len(scores)) if scores else None,
        best_health_score=max(scores) if scores else None,
        score_change=score_change,
    )

    return DashboardResponse(
        stats=stats,
        recent_scans=recent_scans,
        score_trend=trend_points,
        category_averages=category_averages,
        active_scans=active_scans,
    )


def _category_averages(
    completed_scans: list[Scan],
    project_map: dict[UUID, Project],
) -> list[CategoryAverage]:
    latest_by_project: dict[UUID, Scan] = {}
    for scan in sorted(completed_scans, key=lambda s: s.completed_at or s.created_at):
        latest_by_project[scan.project_id] = scan

    totals: dict[str, list[int]] = {cat: [] for cat in AUDIT_CATEGORIES}
    for scan in latest_by_project.values():
        for cat, field in CATEGORY_FIELDS.items():
            value = getattr(scan, field, None)
            if value is not None:
                totals[cat].append(value)

    return [
        CategoryAverage(
            category=cat,
            score=round(sum(values) / len(values)) if values else 100,
            project_count=len(values),
        )
        for cat, values in totals.items()
    ]


def _active_scans(rows: list[tuple[Scan, Project]]) -> list[ActiveScanItem]:
    items: list[ActiveScanItem] = []
    for scan, project in rows:
        if scan.status not in ("queued", "running"):
            continue
        items.append(
            ActiveScanItem(
                scan_id=scan.id,
                project_id=project.id,
                project_name=project.name,
                status=scan.status,
                created_at=scan.created_at,
            )
        )
    return items


async def compare_scans(
    db: AsyncSession,
    user_id: UUID,
    project_id: UUID,
    base_scan_id: UUID,
    target_scan_id: UUID,
) -> ScanCompareResponse | None:
    result = await db.execute(
        select(Scan)
        .options(joinedload(Scan.project))
        .where(
            Scan.user_id == user_id,
            Scan.project_id == project_id,
            Scan.id.in_([base_scan_id, target_scan_id]),
        )
    )
    scans = {scan.id: scan for scan in result.scalars().all()}
    base = scans.get(base_scan_id)
    target = scans.get(target_scan_id)
    if not base or not target:
        return None

    base_resp = _to_scan_response(base)
    target_resp = _to_scan_response(target)

    score_delta = None
    if base.health_score is not None and target.health_score is not None:
        score_delta = target.health_score - base.health_score

    category_deltas: dict[str, int | None] = {}
    for cat, field in CATEGORY_FIELDS.items():
        base_val = getattr(base, field, None)
        target_val = getattr(target, field, None)
        if base_val is not None and target_val is not None:
            category_deltas[cat] = target_val - base_val
        else:
            category_deltas[cat] = None

    improved = score_delta is not None and score_delta > 0

    base_issues = list(
        (
            await db.execute(select(Issue).where(Issue.scan_id == base_scan_id))
        ).scalars().all()
    )
    target_issues = list(
        (
            await db.execute(select(Issue).where(Issue.scan_id == target_scan_id))
        ).scalars().all()
    )
    remediation = compare_remediation(base_issues, target_issues)

    return ScanCompareResponse(
        project_id=project_id,
        base_scan=base_resp,
        target_scan=target_resp,
        score_delta=score_delta,
        issues_delta=target.total_issues - base.total_issues,
        critical_delta=target.critical_count - base.critical_count,
        high_delta=target.high_count - base.high_count,
        medium_delta=target.medium_count - base.medium_count,
        low_delta=target.low_count - base.low_count,
        category_deltas=category_deltas,
        improved=improved,
        fixed_count=remediation.fixed_count,
        new_count=remediation.new_count,
        recurring_count=remediation.recurring_count,
        fixed_issues=[
            RemediationItemResponse(
                title=i.title,
                severity=i.severity,
                rule_id=i.rule_id,
                file_path=i.file_path,
            )
            for i in remediation.fixed_issues
        ],
        new_issues=[
            RemediationItemResponse(
                title=i.title,
                severity=i.severity,
                rule_id=i.rule_id,
                file_path=i.file_path,
            )
            for i in remediation.new_issues
        ],
    )
