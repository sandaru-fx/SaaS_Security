"""Outbound webhooks when audits complete."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

import httpx

from app.models.project import Project
from app.models.scan import Scan

logger = logging.getLogger(__name__)


def notify_scan_complete(scan: Scan, project: Project) -> None:
    if not project.webhook_url:
        return

    payload = {
        "event": "audit.completed",
        "scan_id": str(scan.id),
        "project_id": str(project.id),
        "project_name": project.name,
        "status": scan.status,
        "health_score": scan.health_score,
        "grade": scan.grade,
        "total_issues": scan.total_issues,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "report_url": f"/projects/{project.id}/scans/{scan.id}",
    }

    body = json.dumps(payload)
    headers = {"Content-Type": "application/json"}

    if project.webhook_secret:
        signature = hmac.new(
            project.webhook_secret.encode(),
            body.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers["X-Auditor-Signature"] = f"sha256={signature}"

    try:
        httpx.post(project.webhook_url, content=body, headers=headers, timeout=10.0)
    except Exception as exc:
        logger.warning("Webhook delivery failed for project %s: %s", project.id, exc)
