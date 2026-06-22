"""Stripe checkout, portal, and webhook handling."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.user import User
from app.services.subscription_service import normalize_plan

logger = logging.getLogger(__name__)

PRICE_TO_PLAN: dict[str, str] = {}


def _stripe():
    settings = get_settings()
    if not settings.stripe_enabled:
        raise RuntimeError(
            "Stripe is not configured. Set STRIPE_SECRET_KEY and STRIPE_PRICE_PRO."
        )
    import stripe

    stripe.api_key = settings.stripe_secret_key
    return stripe


def _price_map() -> dict[str, str]:
    settings = get_settings()
    mapping: dict[str, str] = {}
    if settings.stripe_price_pro:
        mapping[settings.stripe_price_pro] = "pro"
    if settings.stripe_price_team:
        mapping[settings.stripe_price_team] = "team"
    return mapping


async def create_checkout_session(
    db: AsyncSession,
    user: User,
    plan: str,
) -> str:
    if plan not in ("pro", "team"):
        raise ValueError("Invalid plan. Choose 'pro' or 'team'.")

    settings = get_settings()
    price_id = settings.stripe_price_pro if plan == "pro" else settings.stripe_price_team
    if not price_id:
        raise ValueError(f"Stripe price not configured for {plan} plan.")

    stripe = _stripe()

    customer_id = user.stripe_customer_id
    if not customer_id:
        customer = stripe.Customer.create(
            email=user.email,
            name=" ".join(filter(None, [user.first_name, user.last_name])) or user.email,
            metadata={"user_id": str(user.id), "clerk_id": user.clerk_id},
        )
        customer_id = customer.id
        user.stripe_customer_id = customer_id
        await db.commit()

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{settings.frontend_url}/billing?success=1",
        cancel_url=f"{settings.frontend_url}/billing?canceled=1",
        metadata={"user_id": str(user.id), "plan": plan},
        subscription_data={"metadata": {"user_id": str(user.id), "plan": plan}},
    )
    if not session.url:
        raise RuntimeError("Stripe did not return a checkout URL.")
    return session.url


async def create_portal_session(user: User) -> str:
    if not user.stripe_customer_id:
        raise ValueError("No billing account found. Subscribe to a paid plan first.")

    settings = get_settings()
    stripe = _stripe()
    session = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=f"{settings.frontend_url}/billing",
    )
    return session.url


async def handle_webhook(db: AsyncSession, payload: bytes, signature: str) -> None:
    settings = get_settings()
    if not settings.stripe_webhook_secret:
        raise RuntimeError("Stripe webhook secret is not configured.")

    stripe = _stripe()
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, settings.stripe_webhook_secret
        )
    except Exception as exc:
        raise ValueError(f"Invalid Stripe webhook: {exc}") from exc

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(db, data)
    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        await _handle_subscription_updated(db, data)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(db, data)
    else:
        logger.debug("Unhandled Stripe event: %s", event_type)


async def _handle_checkout_completed(db: AsyncSession, session: dict[str, Any]) -> None:
    user_id = session.get("metadata", {}).get("user_id")
    plan = session.get("metadata", {}).get("plan", "pro")
    subscription_id = session.get("subscription")
    customer_id = session.get("customer")

    if not user_id:
        return

    user = await _get_user_by_id(db, user_id)
    if not user:
        return

    user.plan = normalize_plan(plan)
    if customer_id:
        user.stripe_customer_id = customer_id
    if subscription_id:
        user.stripe_subscription_id = subscription_id
    await db.commit()


async def _handle_subscription_updated(db: AsyncSession, subscription: dict[str, Any]) -> None:
    user_id = subscription.get("metadata", {}).get("user_id")
    customer_id = subscription.get("customer")
    status = subscription.get("status")
    price_id = _first_price_id(subscription)

    user = None
    if user_id:
        user = await _get_user_by_id(db, user_id)
    if not user and customer_id:
        user = await _get_user_by_customer(db, customer_id)
    if not user:
        return

    plan = _price_map().get(price_id, user.plan)
    if status in ("active", "trialing"):
        user.plan = normalize_plan(plan)
        user.stripe_subscription_id = subscription.get("id")
        user.stripe_customer_id = customer_id or user.stripe_customer_id
    elif status in ("canceled", "unpaid", "past_due"):
        user.plan = "free"
    await db.commit()


async def _handle_subscription_deleted(db: AsyncSession, subscription: dict[str, Any]) -> None:
    customer_id = subscription.get("customer")
    user = await _get_user_by_customer(db, customer_id)
    if not user:
        return
    user.plan = "free"
    user.stripe_subscription_id = None
    await db.commit()


def _first_price_id(subscription: dict[str, Any]) -> str | None:
    items = subscription.get("items", {}).get("data", [])
    if not items:
        return None
    return items[0].get("price", {}).get("id")


async def _get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    from uuid import UUID

    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    return result.scalar_one_or_none()


async def _get_user_by_customer(db: AsyncSession, customer_id: str | None) -> User | None:
    if not customer_id:
        return None
    result = await db.execute(select(User).where(User.stripe_customer_id == customer_id))
    return result.scalar_one_or_none()
