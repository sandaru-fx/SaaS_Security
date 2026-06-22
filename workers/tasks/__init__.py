from celery_app import celery_app


@celery_app.task(name="tasks.ping")
def ping() -> dict:
    """Placeholder task to verify worker is running."""
    return {"status": "ok", "message": "Worker is alive"}


@celery_app.task(name="tasks.run_audit")
def run_audit(project_id: str) -> dict:
    """Placeholder for Phase 4 scan engine."""
    return {
        "status": "queued",
        "project_id": project_id,
        "message": "Audit pipeline not implemented yet (Phase 4)",
    }
