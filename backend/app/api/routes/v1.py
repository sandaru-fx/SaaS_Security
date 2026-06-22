from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_key_deps import get_user_jwt_or_api_key
from app.database import get_db
from app.models.user import User
from app.schemas.scan import ScanResponse
from app.services import project_service, scan_service

router = APIRouter(prefix="/v1", tags=["api-v1"])


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
async def trigger_scan_api(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_user_jwt_or_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        scan = await scan_service.create_scan(db, current_user, project)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan_service.dispatch_scan(str(scan.id), background_tasks)
    return _to_scan_response(scan)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_api(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_user_jwt_or_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanResponse:
    scan = await scan_service.get_scan(db, current_user.id, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_scan_response(scan)
