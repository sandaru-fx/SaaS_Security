"""Enterprise feature gates."""

from app.models.user import User
from app.services.subscription_service import normalize_plan


def has_api_access(user: User) -> bool:
    return normalize_plan(user.plan) in ("pro", "team")


def has_enterprise(user: User) -> bool:
    return normalize_plan(user.plan) == "team"
