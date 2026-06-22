"""Lightweight additive migrations for PostgreSQL and SQLite."""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger(__name__)

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
    ("users", "github_pat", "TEXT"),
    ("projects", "domain_verification_token", "VARCHAR(64)"),
    ("projects", "domain_verified", "BOOLEAN"),
    ("projects", "domain_verified_at", "TIMESTAMP WITH TIME ZONE"),
    ("projects", "pr_checks_enabled", "BOOLEAN"),
    ("projects", "active_dast_enabled", "BOOLEAN"),
    ("projects", "browser_dast_enabled", "BOOLEAN"),
    ("projects", "api_spec_url", "VARCHAR(500)"),
    ("projects", "auth_config", "TEXT"),
    ("projects", "asm_enabled", "BOOLEAN"),
    ("projects", "asm_root_domain", "VARCHAR(255)"),
    ("projects", "cloud_provider", "VARCHAR(20)"),
    ("projects", "cloud_config", "TEXT"),
]

SQLITE_COLUMN_DEFAULTS: dict[tuple[str, str], str] = {
    ("users", "email_alerts_enabled"): "DEFAULT 1",
    ("projects", "domain_verified"): "DEFAULT 0",
    ("projects", "pr_checks_enabled"): "DEFAULT 0",
    ("projects", "active_dast_enabled"): "DEFAULT 0",
    ("projects", "browser_dast_enabled"): "DEFAULT 0",
    ("projects", "asm_enabled"): "DEFAULT 0",
}


async def run_additive_migrations(conn: AsyncConnection) -> None:
    if conn.dialect.name == "sqlite":
        for table, column, col_type in ADDITIVE_COLUMNS:
            await _sqlite_add_column(conn, table, column, col_type)
        return

    for table, column, col_type in ADDITIVE_COLUMNS:
        try:
            await conn.execute(
                text(
                    f'ALTER TABLE "{table}" '
                    f'ADD COLUMN IF NOT EXISTS "{column}" {col_type}'
                )
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("Additive migration failed for %s.%s: %s", table, column, exc)


async def _sqlite_add_column(
    conn: AsyncConnection, table: str, column: str, col_type: str
) -> None:
    result = await conn.execute(text(f"PRAGMA table_info({table})"))
    existing = {row[1] for row in result.fetchall()}
    if column in existing:
        return
    sqlite_type = _sqlite_type(col_type)
    default = SQLITE_COLUMN_DEFAULTS.get((table, column), "")
    sql = f"ALTER TABLE {table} ADD COLUMN {column} {sqlite_type} {default}".strip()
    try:
        await conn.execute(text(sql))
    except Exception as exc:  # pragma: no cover
        logger.warning("SQLite migration failed for %s.%s: %s", table, column, exc)


def _sqlite_type(col_type: str) -> str:
    upper = col_type.upper()
    if "BOOL" in upper:
        return "INTEGER"
    if "TIMESTAMP" in upper:
        return "TEXT"
    if "INTEGER" in upper:
        return "INTEGER"
    if "TEXT" in upper:
        return "TEXT"
    return "VARCHAR"
