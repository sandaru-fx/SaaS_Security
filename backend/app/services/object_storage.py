"""Local disk + optional S3 project file storage."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from app.config import get_settings

logger = logging.getLogger(__name__)


def is_s3_enabled() -> bool:
    settings = get_settings()
    return settings.storage_backend == "s3" and bool(settings.s3_bucket)


def project_local_dir(user_id: str, project_id: str) -> Path:
    settings = get_settings()
    return Path(settings.upload_dir) / user_id / project_id


def storage_path_for(user_id: str, project_id: str) -> str:
    settings = get_settings()
    if is_s3_enabled():
        return f"s3://{settings.s3_bucket}/{user_id}/{project_id}"
    return str(project_local_dir(user_id, project_id))


def _s3_client():
    import boto3

    settings = get_settings()
    kwargs: dict = {}
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        kwargs["aws_access_key_id"] = settings.aws_access_key_id
        kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
    return boto3.client("s3", region_name=settings.s3_region or None, **kwargs)


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    without = uri[len("s3://") :]
    bucket, _, prefix = without.partition("/")
    normalized = prefix.rstrip("/")
    return bucket, f"{normalized}/" if normalized else ""


def _cache_dir(storage_path: str) -> Path:
    settings = get_settings()
    if storage_path.startswith("s3://"):
        _, prefix = _parse_s3_uri(storage_path)
        safe = prefix.replace("/", "_").strip("_") or "project"
        return Path(settings.upload_dir) / ".cache" / safe
    return Path(storage_path)


def upload_local_dir_to_s3(local_dir: Path, user_id: str, project_id: str) -> None:
    if not is_s3_enabled() or not local_dir.exists():
        return
    settings = get_settings()
    client = _s3_client()
    prefix = f"{user_id}/{project_id}/"
    for file_path in local_dir.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(local_dir).as_posix()
        client.upload_file(str(file_path), settings.s3_bucket, prefix + rel)
    logger.info("Uploaded project %s to s3://%s/%s", project_id, settings.s3_bucket, prefix)


def download_s3_to_local(storage_path: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    bucket, prefix = _parse_s3_uri(storage_path)
    client = _s3_client()
    paginator = client.get_paginator("list_objects_v2")
    found = False
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            found = True
            rel = key[len(prefix) :] if prefix and key.startswith(prefix) else key
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(target))
    if not found:
        raise FileNotFoundError(f"No objects found at {storage_path}")
    return dest_dir


def resolve_project_dir(storage_path: str) -> Path:
    if storage_path.startswith("s3://"):
        cache = _cache_dir(storage_path)
        if not any(cache.rglob("*")):
            download_s3_to_local(storage_path, cache)
        return cache

    settings = get_settings()
    path = Path(storage_path)
    if path.is_absolute() and path.exists():
        return path

    candidates = [
        Path.cwd() / path,
        Path("/app") / path,
        Path("/backend") / path,
    ]
    if not path.is_absolute():
        candidates.insert(0, Path(settings.upload_dir) / path)
        candidates.insert(0, project_local_dir(path.parts[-2], path.parts[-1]) if len(path.parts) >= 2 else Path(settings.upload_dir) / path)

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path.cwd() / path


def finalize_project_storage(user_id: str, project_id: str, local_dir: Path) -> str:
    if is_s3_enabled():
        upload_local_dir_to_s3(local_dir, user_id, project_id)
    return storage_path_for(user_id, project_id)


def remove_project_storage(user_id: str, project_id: str, storage_path: str | None) -> None:
    local = project_local_dir(user_id, project_id)
    if local.exists():
        shutil.rmtree(local, ignore_errors=True)

    if not storage_path or not storage_path.startswith("s3://"):
        return

    bucket, prefix = _parse_s3_uri(storage_path)
    client = _s3_client()
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            client.delete_objects(Bucket=bucket, Delete={"Objects": keys})

    cache = _cache_dir(storage_path)
    if cache.exists():
        shutil.rmtree(cache, ignore_errors=True)
