from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.issue import Issue
from app.models.user import User
from app.schemas.scan import (
    AuditChatRequest,
    AuditChatResponse,
    AuditReportResponse,
    IssueListResponse,
    IssueResponse,
    ScanListResponse,
    ScanResponse,
)
from app.services import audit_report, project_service, scan_service
from app.services.pdf_service import generate_audit_pdf
from app.services.subscription_service import has_feature

router = APIRouter(tags=["scans"])


def _to_scan_response(scan) -> ScanResponse:
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


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def start_scan(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    try:
        scan = await scan_service.create_scan(db, current_user, project)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    scan_service.dispatch_scan(str(scan.id), background_tasks)
    return _to_scan_response(scan)


@router.get("/projects/{project_id}/scans", response_model=ScanListResponse)
async def list_scans(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanListResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    scans, total = await scan_service.list_project_scans(db, current_user.id, project_id)
    return ScanListResponse(
        scans=[_to_scan_response(s) for s in scans],
        total=total,
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanResponse:
    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _to_scan_response(scan)


@router.get("/scans/{scan_id}/issues", response_model=IssueListResponse)
async def list_scan_issues(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
) -> IssueListResponse:
    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    query = select(Issue).where(Issue.scan_id == scan_id)
    if severity:
        query = query.where(Issue.severity == severity)
    if category:
        query = query.where(Issue.category == category)
    query = query.order_by(Issue.created_at.asc())

    result = await db.execute(query)
    issues = list(result.scalars().all())
    from app.services.report_service import sort_issues_by_priority
    issues = sort_issues_by_priority(issues)
    return IssueListResponse(
        issues=[audit_report.issue_to_response(i) for i in issues],
        total=len(issues),
    )


@router.get("/scans/{scan_id}/report", response_model=AuditReportResponse)
async def get_audit_report(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuditReportResponse:
    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return await audit_report.build_audit_report(db, scan)


@router.get("/scans/{scan_id}/report/pdf")
async def download_audit_pdf(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    if not has_feature(current_user, "pdf_export"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PDF export is a Pro feature. Upgrade your plan to download reports.",
        )

    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PDF is available only for completed audits.",
        )

    project = await project_service.get_user_project(db, current_user.id, scan.project_id)
    report = await audit_report.build_audit_report(db, scan)
    pdf_bytes = generate_audit_pdf(report, project_name=project.name if project else "Project")

    filename = f"audit-report-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/chat", response_model=AuditChatResponse)
async def chat_with_audit(
    scan_id: UUID,
    payload: AuditChatRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuditChatResponse:
    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Chat is available only for completed audits.",
        )

    result = await db.execute(select(Issue).where(Issue.scan_id == scan_id))
    issues = list(result.scalars().all())

    from app.services.ai_chat import chat_with_audit as run_chat

    allow_deep = has_feature(current_user, "deep_audit")
    response = run_chat(
        scan,
        issues,
        payload.message,
        [m.model_dump() for m in payload.history],
        allow_deep_audit=allow_deep,
    )
    return AuditChatResponse(**response)
