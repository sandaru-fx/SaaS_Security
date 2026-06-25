"""Email and Slack alerts for audit completion."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from app.config import get_settings
from app.models.scan import Scan
from app.models.user import User

logger = logging.getLogger(__name__)


def send_critical_alert(user: User, scan: Scan, project_name: str) -> None:
    if not user.email_alerts_enabled:
        return
    if scan.critical_count == 0:
        return

    settings = get_settings()
    if not settings.smtp_host:
        logger.info(
            "Critical alert skipped (SMTP not configured): user=%s scan=%s critical=%d",
            user.email,
            scan.id,
            scan.critical_count,
        )
        return

    msg = EmailMessage()
    msg["Subject"] = f"[Auditor] {scan.critical_count} critical issues in {project_name}"
    msg["From"] = settings.smtp_from_email or settings.smtp_user
    msg["To"] = user.email
    msg.set_content(
        f"Audit completed for {project_name}.\n\n"
        f"Health Score: {scan.health_score}/100 (Grade {scan.grade})\n"
        f"Critical issues: {scan.critical_count}\n"
        f"High issues: {scan.high_count}\n\n"
        f"Review the full report in your dashboard."
    )

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
    except Exception as exc:
        logger.warning("Failed to send alert email to %s: %s", user.email, exc)


def send_scan_slack_alert(user: User, scan: Scan, project_name: str) -> None:
    if not user.slack_alerts_enabled or not user.slack_webhook_url:
        return

    settings = get_settings()
    report_path = f"/projects/{scan.project_id}/scans/{scan.id}"
    report_url = f"{settings.frontend_url.rstrip('/')}{report_path}"

    text = (
        f"Audit complete: *{project_name}*\n"
        f"Score: {scan.health_score}/100 (Grade {scan.grade})\n"
        f"Issues: {scan.total_issues} total "
        f"({scan.critical_count} critical, {scan.high_count} high)\n"
        f"<{report_url}|View report>"
    )

    try:
        httpx.post(
            user.slack_webhook_url,
            json={"text": text},
            timeout=10.0,
        )
    except Exception as exc:
        logger.warning("Slack alert failed for user %s: %s", user.email, exc)
