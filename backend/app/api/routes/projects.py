from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.project import (
    DomainVerificationInfo,
    ProjectAuthUpdate,
    ProjectCreateApi,
    ProjectCreateGithub,
    ProjectCreateLocal,
    ProjectCreateWebsite,
    ProjectListResponse,
    ProjectPrChecksUpdate,
    ProjectResponse,
    ProjectUpdate,
)
from app.services.domain_verification import (
    mark_domain_verified,
    verification_instructions,
    verify_domain_ownership,
    generate_verification_token,
)
from app.services.subscription_service import has_feature
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


@router.post("/api", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_api_project(
    payload: ProjectCreateApi,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    try:
        project = await project_service.create_api_project(db, current_user, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProjectResponse.model_validate(project)


@router.patch("/{project_id}/auth", response_model=ProjectResponse)
async def update_project_auth(
    project_id: UUID,
    payload: ProjectAuthUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.source_type not in ("website", "api"):
        raise HTTPException(
            status_code=400,
            detail="Auth configuration applies to website and api projects only",
        )
    project = await project_service.update_project_auth(db, project, payload)
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


@router.post("/folder", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def upload_folder_project(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    name: Annotated[str, Form()],
    files: Annotated[list[UploadFile], File()],
    description: Annotated[str | None, Form()] = None,
) -> ProjectResponse:
    try:
        project = await project_service.create_folder_project(
            db, current_user, name, files, description
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProjectResponse.model_validate(project)


@router.post("/local", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_local_project(
    payload: ProjectCreateLocal,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    try:
        project = await project_service.create_local_project(db, current_user, payload)
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


@router.get("/{project_id}/domain-verification", response_model=DomainVerificationInfo)
async def get_domain_verification(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DomainVerificationInfo:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.source_type not in ("website", "api"):
        raise HTTPException(status_code=400, detail="Domain verification applies to website and api projects only")
    if not project.domain_verification_token:
        project.domain_verification_token = generate_verification_token()
        await db.commit()
        await db.refresh(project)
    info = verification_instructions(project)
    return DomainVerificationInfo(
        domain=info["domain"],
        token=info["token"],
        dns_record_name=info["dns_record_name"],
        dns_record_value=info["dns_record_value"],
        meta_tag=info["meta_tag"],
        verified=project.domain_verified,
    )


@router.post("/{project_id}/verify-domain", response_model=DomainVerificationInfo)
async def verify_domain(
    project_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DomainVerificationInfo:
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.source_type not in ("website", "api"):
        raise HTTPException(status_code=400, detail="Domain verification applies to website and api projects only")
    if not project.domain_verification_token:
        project.domain_verification_token = generate_verification_token()

    ok, message = verify_domain_ownership(project)
    if ok:
        mark_domain_verified(project)
        project.status_message = message
    else:
        raise HTTPException(status_code=400, detail=message)

    await db.commit()
    await db.refresh(project)
    info = verification_instructions(project)
    return DomainVerificationInfo(
        domain=info["domain"],
        token=info["token"],
        dns_record_name=info["dns_record_name"],
        dns_record_value=info["dns_record_value"],
        meta_tag=info["meta_tag"],
        verified=project.domain_verified,
    )


@router.patch("/{project_id}/pr-checks", response_model=ProjectResponse)
async def update_pr_checks(
    project_id: UUID,
    payload: ProjectPrChecksUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    if not has_feature(current_user, "private_repos"):
        raise HTTPException(
            status_code=403,
            detail="PR checks require Pro or Team plan.",
        )
    project = await project_service.get_user_project(db, current_user.id, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.source_type != "github":
        raise HTTPException(status_code=400, detail="PR checks apply to GitHub projects only")
    project.pr_checks_enabled = payload.enabled
    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)
