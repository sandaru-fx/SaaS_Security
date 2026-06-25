import pytest

from app.services.object_storage import storage_path_for


def test_local_storage_path(monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    from app.config import get_settings

    get_settings.cache_clear()
    path = storage_path_for("user-1", "proj-1")
    assert path.endswith("user-1/proj-1") or path.endswith("user-1\\proj-1")


def test_s3_storage_path(monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "s3")
    monkeypatch.setenv("S3_BUCKET", "my-auditor-bucket")
    from app.config import get_settings

    get_settings.cache_clear()
    path = storage_path_for("user-1", "proj-1")
    assert path == "s3://my-auditor-bucket/user-1/proj-1"
    get_settings.cache_clear()
