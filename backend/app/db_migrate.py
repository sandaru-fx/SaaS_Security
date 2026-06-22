"""Lightweight additive migrations.

SQLAlchemy's ``create_all`` creates missing tables but never alters existing
ones. When we add new columns to a model we run idempotent ``ADD COLUMN IF NOT
EXISTS`` statements so existing databases stay in sync without Alembic.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger(__name__)

# (table, column, type) tuples. PostgreSQL supports ADD COLUMN IF NOT EXISTS.
ADDITIVE_COLUMNS: list[tuple[str, str, str]] = [
    ("scans", "health_score", "INTEGER"),
    ("scans", "security_score", "INTEGER"),
    ("scans", "architecture_score", "INTEGER"),
    ("scans", "performance_score", "INTEGER"),
    ("scans", "quality_score", "INTEGER"),
    ("scans", "devops_score", "INTEGER"),
    ("scans", "grade", "VARCHAR(2)"),
    ("scans", "ai_summary", "TEXT"),
    ("scans", "ai_business_risk", "TEXT"),
    ("scans", "ai_recommendations", "TEXT"),
    ("scans", "ai_provider", "VARCHAR(20)"),
    ("issues", "business_risk", "TEXT"),
    ("users", "plan", "VARCHAR(20)"),
    ("users", "stripe_customer_id", "VARCHAR(255)"),
    ("users", "stripe_subscription_id", "VARCHAR(255)"),
    ("users", "scans_used_this_period", "INTEGER"),
    ("users", "billing_period_start", "TIMESTAMP WITH TIME ZONE"),
    ("users", "email_alerts_enabled", "BOOLEAN"),
    ("issues", "dismissed", "BOOLEAN"),
    ("issues", "dismissed_reason", "TEXT"),
    ("issues", "dismissed_at", "TIMESTAMP WITH TIME ZONE"),
    ("projects", "webhook_url", "VARCHAR(500)"),
    ("projects", "webhook_secret", "VARCHAR(255)"),
]


async def run_additive_migrations(conn: AsyncConnection) -> None:
    if conn.dialect.name == "sqlite":
        return

    for table, column, col_type in ADDITIVE_COLUMNS:
        try:
            await conn.execute(
                text(
                    f'ALTER TABLE "{table}" '
                    f'ADD COLUMN IF NOT EXISTS "{column}" {col_type}'
                )
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Additive migration failed for %s.%s: %s", table, column, exc
            )
