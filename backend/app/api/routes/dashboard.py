from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.dashboard import DashboardResponse, ScanCompareResponse
from app.services import dashboard_service, project_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardResponse)
async def get_dashboard(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DashboardResponse:
    return await dashboard_service.get_dashboard(db, current_user.id)


@router.get(
    "/projects/{project_id}/scans/compare",
    response_model=ScanCompareResponse,
)
async def compare_project_scans(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    base: Annotated[UUID, Query(description="Earlier scan to compare from")],
    target: Annotated[UUID, Query(description="Later scan to compare to")],
) -> ScanCompareResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    comparison = await dashboard_service.compare_scans(
        db, current_user.id, project_id, base, target
    )
    if not comparison:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return comparison
