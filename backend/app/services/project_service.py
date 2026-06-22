import json
import tempfile
from pathlib import Path
from uuid import UUID

import httpx
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.user import User
from app.schemas.project import (
    AuthConfig,
    ProjectAsmUpdate,
    ProjectAuthUpdate,
    ProjectCreateApi,
    ProjectCreateGithub,
    ProjectCreateLocal,
    ProjectCreateWebsite,
    ProjectUpdate,
)
from app.scanners.website_scanner import normalize_website_url, validate_website_url
from app.services.github import build_github_headers, build_github_zipball_url, parse_github_url
from app.services.domain_verification import generate_verification_token
from app.services.subscription_service import has_feature
from app.services.storage import (
    count_project_files,
    delete_project_dir,
    ensure_project_dir,
    flatten_single_root_folder,
    safe_extract_zip,
    save_uploaded_files,
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
        token = user.github_pat if has_feature(user, "private_repos") else None
        await _download_github_repo(owner, repo, payload.branch.strip(), project_dir, token=token)
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


async def create_folder_project(
    db: AsyncSession,
    user: User,
    name: str,
    uploads: list[UploadFile],
    description: str | None = None,
) -> Project:
    if not uploads:
        raise ValueError("No files selected. Choose a project folder to upload.")

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    total_bytes = 0
    file_payloads: list[tuple[str, bytes]] = []

    for upload in uploads:
        relative_path = (upload.filename or "file").replace("\\", "/").strip()
        if not relative_path:
            continue
        content = await upload.read()
        total_bytes += len(content)
        if total_bytes > max_bytes:
            raise ValueError(f"Folder too large. Maximum size is {settings.max_upload_size_mb}MB")
        file_payloads.append((relative_path, content))

    if len(file_payloads) > settings.max_zip_files:
        raise ValueError(f"Too many files (max {settings.max_zip_files})")

    project = Project(
        user_id=user.id,
        name=name.strip(),
        description=description,
        source_type="folder",
        status="processing",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    project_dir = ensure_project_dir(str(user.id), str(project.id))
    project.storage_path = str(Path(settings.upload_dir) / str(user.id) / str(project.id))

    try:
        saved = save_uploaded_files(file_payloads, project_dir)
        flatten_single_root_folder(project_dir)
        project.file_count = count_project_files(project_dir)
        if project.file_count == 0:
            raise ValueError("No scannable files found in the selected folder")
        project.status = "ready"
        project.status_message = f"Uploaded {project.file_count} files from local folder ({saved} saved)"
    except Exception as exc:
        project.status = "failed"
        project.status_message = str(exc)
        delete_project_dir(str(user.id), str(project.id))

    await db.commit()
    await db.refresh(project)
    return project


def _resolve_local_path(raw_path: str) -> Path:
    if not settings.local_paths_enabled:
        raise ValueError(
            "Local folder paths are disabled in production. "
            "Use Open Folder upload or set ALLOW_LOCAL_PROJECT_PATHS=true for local dev."
        )

    path = Path(raw_path.strip()).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"Folder does not exist: {path}")
    if not path.is_dir():
        raise ValueError(f"Path is not a folder: {path}")

    if settings.local_projects_root:
        root = Path(settings.local_projects_root).expanduser().resolve()
        if not str(path).startswith(str(root)):
            raise ValueError(f"Folder must be under {root}")

    return path


async def create_local_project(
    db: AsyncSession,
    user: User,
    payload: ProjectCreateLocal,
) -> Project:
    folder = _resolve_local_path(payload.local_path)

    project = Project(
        user_id=user.id,
        name=payload.name.strip(),
        description=payload.description,
        source_type="local",
        repo_url=str(folder),
        status="processing",
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    try:
        project.storage_path = str(folder)
        project.file_count = count_project_files(folder)
        if project.file_count == 0:
            raise ValueError("Folder is empty or contains no readable files")
        project.status = "ready"
        project.status_message = (
            f"Linked local folder with {project.file_count} files (scans read directly from disk)"
        )
    except Exception as exc:
        project.status = "failed"
        project.status_message = str(exc)

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
        domain_verification_token=generate_verification_token(),
        domain_verified=False,
        status="processing",
        active_dast_enabled=bool(payload.active_dast_enabled),
        asm_enabled=bool(payload.asm_enabled),
        asm_root_domain=_derive_asm_root(normalized_url) if payload.asm_enabled else None,
        auth_config=_serialize_auth(payload.auth),
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
        project.status_message = (
            f"Website reachable at {normalized_url}. "
            "Verify domain ownership before scanning."
        )
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


def _serialize_auth(auth: AuthConfig | None) -> str | None:
    if not auth or auth.type.value == "none":
        return None
    data = auth.model_dump(exclude_none=True)
    return json.dumps(data)


def deserialize_auth(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


async def create_api_project(
    db: AsyncSession,
    user: User,
    payload: ProjectCreateApi,
) -> Project:
    if not payload.ownership_confirmed:
        raise ValueError("You must confirm ownership or permission to scan this API")

    spec_url = payload.api_spec_url.strip()
    if not spec_url.startswith(("http://", "https://")):
        raise ValueError("API spec URL must start with http:// or https://")

    project = Project(
        user_id=user.id,
        name=payload.name.strip(),
        description=payload.description,
        source_type="api",
        repo_url=spec_url,
        api_spec_url=spec_url,
        domain_verification_token=generate_verification_token(),
        domain_verified=False,
        status="processing",
        active_dast_enabled=True,
        asm_enabled=bool(payload.asm_enabled),
        asm_root_domain=_derive_asm_root(spec_url) if payload.asm_enabled else None,
        auth_config=_serialize_auth(payload.auth),
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
            response = await client.get(spec_url)
            if response.status_code >= 400:
                raise ValueError(f"Could not load OpenAPI spec — HTTP {response.status_code}")
        project.status = "ready"
        project.status_message = (
            f"OpenAPI spec reachable at {spec_url}. "
            "Verify domain ownership of the API host before scanning."
        )
    except httpx.HTTPError as exc:
        project.status = "failed"
        project.status_message = f"Could not reach API spec URL: {exc}"

    await db.commit()
    await db.refresh(project)
    return project


async def update_project_auth(
    db: AsyncSession,
    project: Project,
    payload: ProjectAuthUpdate,
) -> Project:
    project.auth_config = _serialize_auth(payload.auth)
    if payload.active_dast_enabled is not None:
        project.active_dast_enabled = bool(payload.active_dast_enabled)
    if payload.asm_enabled is not None:
        project.asm_enabled = bool(payload.asm_enabled)
        if project.asm_enabled and not project.asm_root_domain:
            project.asm_root_domain = _derive_asm_root(project.repo_url or "")
    await db.commit()
    await db.refresh(project)
    return project


async def update_project_asm(
    db: AsyncSession,
    project: Project,
    payload: ProjectAsmUpdate,
) -> Project:
    project.asm_enabled = bool(payload.enabled)
    if payload.root_domain:
        project.asm_root_domain = payload.root_domain.strip().lower()
    elif project.asm_enabled and not project.asm_root_domain:
        project.asm_root_domain = _derive_asm_root(project.repo_url or "")
    await db.commit()
    await db.refresh(project)
    return project


def _derive_asm_root(url: str) -> str | None:
    from urllib.parse import urlparse

    if not url:
        return None
    raw = url.strip().lower()
    if "://" in raw:
        host = urlparse(raw).hostname or ""
    else:
        host = raw.strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


async def delete_project(db: AsyncSession, user: User, project: Project) -> None:
    if project.source_type in ("website", "local", "api"):
        pass
    else:
        delete_project_dir(str(user.id), str(project.id))
    await db.delete(project)
    await db.commit()


async def _download_github_repo(
    owner: str,
    repo: str,
    branch: str,
    dest_dir: Path,
    *,
    token: str | None = None,
) -> None:
    url = build_github_zipball_url(owner, repo, branch)
    headers = build_github_headers(token)

    async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 404:
            if token:
                raise ValueError(
                    f"Repository not found or branch '{branch}' does not exist. "
                    "Check your GitHub token has repo access."
                )
            raise ValueError(
                f"Repository not found or branch '{branch}' does not exist. "
                "Public repos work on Free. Private repos require Pro and a GitHub PAT "
                "(set in Enterprise settings)."
            )
        if response.status_code == 401:
            raise ValueError("GitHub authentication failed. Check your Personal Access Token.")
        if response.status_code != 200:
            raise ValueError(f"GitHub download failed (HTTP {response.status_code})")

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(response.content)
            tmp_path = Path(tmp.name)

    try:
        safe_extract_zip(tmp_path, dest_dir)
    finally:
        tmp_path.unlink(missing_ok=True)
