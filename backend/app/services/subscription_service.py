"""Subscription plans, usage limits, and feature gates."""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.user import User

PLAN_LIMITS: dict[str, dict] = {
    "free": {
        "label": "Free",
        "scan_limit": 2,
        "pdf_export": False,
        "sbom_export": False,
        "deep_audit": False,
        "private_repos": False,
        "price_display": "$0/mo",
    },
    "pro": {
        "label": "Pro",
        "scan_limit": None,
        "pdf_export": True,
        "sbom_export": True,
        "deep_audit": True,
        "private_repos": True,
        "price_display": "$19/mo",
    },
    "team": {
        "label": "Team",
        "scan_limit": None,
        "pdf_export": True,
        "sbom_export": True,
        "deep_audit": True,
        "private_repos": True,
        "price_display": "$49/mo",
    },
}


def normalize_plan(plan: str | None) -> str:
    if plan in PLAN_LIMITS:
        return plan
    return "free"


def get_plan_config(plan: str | None) -> dict:
    return PLAN_LIMITS[normalize_plan(plan)]


def reset_billing_period_if_needed(user: User) -> None:
    if user.scans_used_this_period is None:
        user.scans_used_this_period = 0
    now = datetime.now(timezone.utc)
    if user.billing_period_start is None:
        user.billing_period_start = now
        user.scans_used_this_period = 0
        return

    start = user.billing_period_start
    if start.year != now.year or start.month != now.month:
        user.billing_period_start = now
        user.scans_used_this_period = 0


def scans_remaining(user: User) -> int | None:
    config = get_plan_config(user.plan)
    limit = config["scan_limit"]
    if limit is None:
        return None
    reset_billing_period_if_needed(user)
    return max(0, limit - user.scans_used_this_period)


def can_start_scan(user: User) -> tuple[bool, str]:
    reset_billing_period_if_needed(user)
    config = get_plan_config(user.plan)
    limit = config["scan_limit"]
    if limit is None:
        return True, ""
    if user.scans_used_this_period >= limit:
        return (
            False,
            f"Monthly scan limit reached ({limit} on {config['label']} plan). "
            "Upgrade to Pro for unlimited audits.",
        )
    return True, ""


def record_scan_usage(user: User) -> None:
    reset_billing_period_if_needed(user)
    user.scans_used_this_period += 1


def has_feature(user: User, feature: str) -> bool:
    return bool(get_plan_config(user.plan).get(feature))


def build_subscription_info(user: User) -> dict:
    config = get_plan_config(user.plan)
    reset_billing_period_if_needed(user)
    limit = config["scan_limit"]
    remaining = scans_remaining(user)

    return {
        "plan": normalize_plan(user.plan),
        "plan_label": config["label"],
        "price_display": config["price_display"],
        "scans_used": user.scans_used_this_period,
        "scan_limit": limit,
        "scans_remaining": remaining,
        "features": {
            "pdf_export": config["pdf_export"],
            "sbom_export": config.get("sbom_export", False),
            "deep_audit": config["deep_audit"],
            "private_repos": config["private_repos"],
            "unlimited_scans": limit is None,
        },
        "billing_period_start": user.billing_period_start,
        "stripe_customer_id": user.stripe_customer_id,
        "has_active_subscription": user.plan in ("pro", "team") and bool(
            user.stripe_subscription_id
        ),
    }
