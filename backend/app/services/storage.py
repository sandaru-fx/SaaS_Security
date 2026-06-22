import shutil
import zipfile
from pathlib import Path

from app.config import get_settings

settings = get_settings()


def get_storage_root() -> Path:
    root = Path(settings.upload_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_project_dir(user_id: str, project_id: str) -> Path:
    return get_storage_root() / str(user_id) / str(project_id)


def ensure_project_dir(user_id: str, project_id: str) -> Path:
    path = get_project_dir(user_id, project_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def delete_project_dir(user_id: str, project_id: str) -> None:
    path = get_project_dir(user_id, project_id)
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def count_project_files(project_dir: Path) -> int:
    if not project_dir.exists():
        return 0
    return sum(1 for item in project_dir.rglob("*") if item.is_file())


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    """Extract zip with zip-slip protection."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as archive:
        if len(archive.namelist()) > settings.max_zip_files:
            raise ValueError(f"ZIP contains too many files (max {settings.max_zip_files})")

        for member in archive.namelist():
            if member.endswith("/"):
                continue
            target = (dest_dir / member).resolve()
            if not str(target).startswith(str(dest_resolved)):
                raise ValueError("Unsafe ZIP path detected")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)


def flatten_single_root_folder(project_dir: Path) -> None:
    """GitHub zipballs extract into a single root folder — lift contents up."""
    entries = [p for p in project_dir.iterdir() if p.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        nested = entries[0]
        for child in nested.iterdir():
            shutil.move(str(child), str(project_dir / child.name))
        shutil.rmtree(nested, ignore_errors=True)


SKIP_UPLOAD_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".turbo",
}


def should_skip_upload_path(relative_path: str) -> bool:
    parts = Path(relative_path.replace("\\", "/")).parts
    return any(part in SKIP_UPLOAD_DIRS for part in parts)


def save_uploaded_files(files: list[tuple[str, bytes]], dest_dir: Path) -> int:
    """Save browser folder upload files with path-traversal protection."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()
    saved = 0

    for relative_path, content in files:
        rel = relative_path.replace("\\", "/").lstrip("/")
        if not rel or should_skip_upload_path(rel):
            continue
        target = (dest_dir / rel).resolve()
        if not str(target).startswith(str(dest_resolved)):
            raise ValueError("Unsafe file path detected in folder upload")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        saved += 1

    return saved
