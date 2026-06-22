"""Email alerts for critical audit findings."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

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
