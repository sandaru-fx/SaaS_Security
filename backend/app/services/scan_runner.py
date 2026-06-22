import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import delete, select

from app.config import get_settings
from app.db_sync import get_sync_session
from app.models.issue import Issue
from app.models.project import Project
from app.models.scan import Scan
from app.scanners.runner import run_all_scanners
from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)


def execute_scan(scan_id: str) -> None:
    """Synchronous scan execution — called by Celery worker or background fallback."""
    session = get_sync_session()
    try:
        scan = session.get(Scan, UUID(scan_id))
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        project = session.get(Project, scan.project_id)
        if not project:
            _fail_scan(session, scan, "Project not found")
            return

        if project.status != "ready" or not project.storage_path:
            _fail_scan(session, scan, "Project source code is not ready for scanning")
            return

        project_dir = _resolve_project_dir(project.storage_path)
        if not project_dir.exists():
            _fail_scan(session, scan, f"Project directory not found: {project_dir}")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.error_message = None
        session.commit()

        findings, scanners_used = run_all_scanners(project_dir)
        _save_findings(session, scan, findings)

        issues = session.execute(
            select(Issue).where(Issue.scan_id == scan.id)
        ).scalars().all()
        from app.services.report_service import apply_scores_to_scan
        apply_scores_to_scan(scan, list(issues))

        scan.scanners_used = ",".join(scanners_used)
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        session.commit()
        logger.info("Scan %s completed with %d issues", scan_id, scan.total_issues)

    except Exception as exc:
        session.rollback()
        scan = session.get(Scan, UUID(scan_id))
        if scan:
            _fail_scan(session, scan, str(exc))
        logger.exception("Scan %s failed", scan_id)
    finally:
        session.close()


def _save_findings(session, scan: Scan, findings: list[ScanFinding]) -> None:
    session.execute(delete(Issue).where(Issue.scan_id == scan.id))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        severity = finding.severity if finding.severity in counts else "medium"
        counts[severity] = counts.get(severity, 0) + 1

        session.add(
            Issue(
                scan_id=scan.id,
                category=finding.category,
                severity=severity,
                title=finding.title[:300],
                description=finding.description,
                impact=finding.impact,
                fix_recommendation=finding.fix_recommendation,
                file_path=finding.file_path or None,
                line_start=finding.line_start,
                line_end=finding.line_end,
                rule_id=finding.rule_id[:200],
                scanner=finding.scanner,
                confidence=finding.confidence,
                extra_data=finding.metadata or None,
            )
        )

    scan.total_issues = len(findings)
    scan.critical_count = counts["critical"]
    scan.high_count = counts["high"]
    scan.medium_count = counts["medium"]
    scan.low_count = counts["low"]


def _fail_scan(session, scan: Scan, message: str) -> None:
    scan.status = "failed"
    scan.error_message = message
    scan.completed_at = datetime.now(timezone.utc)
    session.commit()


def _resolve_project_dir(storage_path: str) -> Path:
    settings = get_settings()
    path = Path(storage_path)
    if path.is_absolute():
        return path

    candidates = [
        Path.cwd() / path,
        Path("/app") / path,
        Path("/backend") / path,
        Path(settings.upload_dir).parent / path if settings.upload_dir else Path.cwd() / path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path.cwd() / path
