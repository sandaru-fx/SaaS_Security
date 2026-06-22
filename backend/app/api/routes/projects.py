from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.project import (
    ProjectCreateGithub,
    ProjectCreateWebsite,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdate,
)
from app.services import project_service

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectListResponse:
    projects, total = await project_service.list_user_projects(db, current_user.id)
    return ProjectListResponse(
        projects=[ProjectResponse.model_validate(p) for p in projects],
        total=total,
    )


@router.post("/github", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_github_project(
    payload: ProjectCreateGithub,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    try:
        project = await project_service.create_github_project(db, current_user, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProjectResponse.model_validate(project)


@router.post("/website", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_website_project(
    payload: ProjectCreateWebsite,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    try:
        project = await project_service.create_website_project(db, current_user, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProjectResponse.model_validate(project)


@router.post("/upload", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def upload_zip_project(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    name: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
    description: Annotated[str | None, Form()] = None,
) -> ProjectResponse:
    try:
        project = await project_service.create_zip_project(
            db, current_user, name, file, description
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProjectResponse.model_validate(project)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return ProjectResponse.model_validate(project)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    payload: ProjectUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    project = await project_service.update_project(db, project, payload)
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    await project_service.delete_project(db, current_user, project)
