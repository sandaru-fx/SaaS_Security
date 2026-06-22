import tempfile
from pathlib import Path
from uuid import UUID

import httpx
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.user import User
from app.schemas.project import ProjectCreateGithub, ProjectCreateWebsite, ProjectUpdate
from app.scanners.website_scanner import normalize_website_url, validate_website_url
from app.services.github import build_github_zipball_url, parse_github_url
from app.services.storage import (
    count_project_files,
    delete_project_dir,
    ensure_project_dir,
    flatten_single_root_folder,
    safe_extract_zip,
)
from app.config import get_settings

settings = get_settings()


async def list_user_projects(db: AsyncSession, user_id: UUID) -> tuple[list[Project], int]:
    result = await db.execute(
        select(Project)
        .where(Project.user_id == user_id)
        .order_by(Project.created_at.desc())
    )
    projects = list(result.scalars().all())
    return projects, len(projects)


async def get_user_project(db: AsyncSession, user_id: UUID, project_id: UUID) -> Project | None:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user_id)
    )
    return result.scalar_one_or_none()


async def create_github_project(
    db: AsyncSession,
    user: User,
    payload: ProjectCreateGithub,
) -> Project:
    owner, repo = parse_github_url(payload.repo_url)
    normalized_url = f"https://github.com/{owner}/{repo}"

    project = Project(
        user_id=user.id,
        name=payload.name.strip(),
        description=payload.description,
        source_type="github",
        repo_url=normalized_url,
        repo_branch=payload.branch.strip(),
        status="processing",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    project_dir = ensure_project_dir(str(user.id), str(project.id))
    project.storage_path = f"{settings.upload_dir}/{user.id}/{project.id}"

    try:
        await _download_github_repo(owner, repo, payload.branch.strip(), project_dir)
        flatten_single_root_folder(project_dir)
        project.file_count = count_project_files(project_dir)
        project.status = "ready"
        project.status_message = f"Cloned {project.file_count} files from {normalized_url}"
    except Exception as exc:
        project.status = "failed"
        project.status_message = str(exc)
        delete_project_dir(str(user.id), str(project.id))

    await db.commit()
    await db.refresh(project)
    return project


async def create_zip_project(
    db: AsyncSession,
    user: User,
    name: str,
    upload: UploadFile,
    description: str | None = None,
) -> Project:
    if not upload.filename or not upload.filename.lower().endswith(".zip"):
        raise ValueError("Only .zip files are supported")

    content = await upload.read()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(content) > max_bytes:
        raise ValueError(f"File too large. Maximum size is {settings.max_upload_size_mb}MB")

    project = Project(
        user_id=user.id,
        name=name.strip(),
        description=description,
        source_type="zip",
        status="processing",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    project_dir = ensure_project_dir(str(user.id), str(project.id))
    project.storage_path = str(Path(settings.upload_dir) / str(user.id) / str(project.id))

    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        try:
            safe_extract_zip(tmp_path, project_dir)
            flatten_single_root_folder(project_dir)
            project.file_count = count_project_files(project_dir)
            project.status = "ready"
            project.status_message = f"Extracted {project.file_count} files from upload"
        finally:
            tmp_path.unlink(missing_ok=True)
    except Exception as exc:
        project.status = "failed"
        project.status_message = str(exc)
        delete_project_dir(str(user.id), str(project.id))

    await db.commit()
    await db.refresh(project)
    return project


async def create_website_project(
    db: AsyncSession,
    user: User,
    payload: ProjectCreateWebsite,
) -> Project:
    if not payload.ownership_confirmed:
        raise ValueError("You must confirm ownership or permission to scan this website")

    try:
        normalized_url = normalize_website_url(payload.website_url)
        validate_website_url(normalized_url)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    project = Project(
        user_id=user.id,
        name=payload.name.strip(),
        description=payload.description,
        source_type="website",
        repo_url=normalized_url,
        status="processing",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=20.0,
            headers={"User-Agent": "AI-Software-Auditor/1.0"},
        ) as client:
            response = await client.head(normalized_url)
            if response.status_code >= 400 or response.status_code == 405:
                response = await client.get(normalized_url)
            if response.status_code >= 400:
                raise ValueError(f"Website returned HTTP {response.status_code}")
        project.status = "ready"
        project.status_message = f"Website reachable at {normalized_url}"
    except httpx.HTTPError as exc:
        project.status = "failed"
        project.status_message = f"Could not reach website: {exc}"

    await db.commit()
    await db.refresh(project)
    return project


async def update_project(
    db: AsyncSession,
    project: Project,
    payload: ProjectUpdate,
) -> Project:
    if payload.name is not None:
        project.name = payload.name.strip()
    if payload.description is not None:
        project.description = payload.description
    await db.commit()
    await db.refresh(project)
    return project


async def delete_project(db: AsyncSession, user: User, project: Project) -> None:
    if project.source_type != "website":
        delete_project_dir(str(user.id), str(project.id))
    await db.delete(project)
    await db.commit()


async def _download_github_repo(owner: str, repo: str, branch: str, dest_dir: Path) -> None:
    url = build_github_zipball_url(owner, repo, branch)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AI-Software-Auditor/1.0",
    }

    async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 404:
            raise ValueError(
                f"Repository not found or branch '{branch}' does not exist. "
                "Only public repositories are supported."
            )
        if response.status_code != 200:
            raise ValueError(f"GitHub download failed (HTTP {response.status_code})")

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(response.content)
            tmp_path = Path(tmp.name)

    try:
        safe_extract_zip(tmp_path, dest_dir)
    finally:
        tmp_path.unlink(missing_ok=True)
