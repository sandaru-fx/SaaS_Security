import sys
from pathlib import Path

from celery_app import celery_app

# Add backend to path so worker can import scan engine
BACKEND_PATHS = [
    Path("/backend"),
    Path(__file__).resolve().parents[1] / "backend",
]
for path in BACKEND_PATHS:
    if path.exists() and str(path) not in sys.path:
        sys.path.insert(0, str(path))


@celery_app.task(name="tasks.ping")
def ping() -> dict:
    return {"status": "ok", "message": "Worker is alive"}


@celery_app.task(name="tasks.run_audit", bind=True, max_retries=1)
def run_audit(self, scan_id: str) -> dict:
    from app.services.scan_runner import execute_scan

    execute_scan(scan_id)
    return {"status": "completed", "scan_id": scan_id}
