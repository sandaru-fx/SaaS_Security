"""Shared helpers for extended scanners."""

from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".turbo",
    "coverage",
    ".pytest_cache",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".sql", ".sh", ".bash", ".ps1",
    ".java", ".go", ".rs", ".php", ".rb", ".cs", ".xml", ".html", ".css",
    ".md", ".dockerfile",
}

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".php", ".rb", ".cs",
}

ROUTE_DIR_NAMES = {"routes", "controllers", "api", "handlers", "views", "endpoints"}


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def rel_path(path: Path, project_dir: Path) -> str:
    return str(path.relative_to(project_dir)).replace("\\", "/")


def iter_files(
    project_dir: Path,
    *,
    extensions: set[str] | None = None,
    include_names: set[str] | None = None,
) -> list[Path]:
    files: list[Path] = []
    for path in project_dir.rglob("*"):
        if not path.is_file() or should_skip(path):
            continue
        if extensions and path.suffix.lower() in extensions:
            files.append(path)
        elif include_names and path.name in include_names:
            files.append(path)
        elif extensions is None and include_names is None:
            files.append(path)
    return files


def iter_code_files(project_dir: Path) -> list[Path]:
    extra = iter_files(project_dir, include_names={".env", ".env.local", "Dockerfile"})
    code = iter_files(project_dir, extensions=CODE_EXTENSIONS)
    seen = {str(p) for p in code}
    for path in extra:
        if str(path) not in seen:
            code.append(path)
    return code


def read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None


def file_to_module_key(rel: str) -> str:
    key = rel.replace("\\", "/")
    if key.endswith(".py"):
        key = key[:-3]
    elif key.endswith((".ts", ".js", ".tsx", ".jsx")):
        key = key.rsplit(".", 1)[0]
    return key.replace("/", ".")


def is_route_file(rel: str) -> bool:
    parts = {part.lower() for part in rel.replace("\\", "/").split("/")}
    return bool(parts & ROUTE_DIR_NAMES)
