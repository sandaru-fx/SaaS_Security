from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.billing import (
    CheckoutRequest,
    CheckoutResponse,
    PlanFeatures,
    PortalResponse,
    PricingPlan,
    PricingResponse,
    SubscriptionResponse,
)
from app.services import stripe_service, subscription_service

router = APIRouter(prefix="/billing", tags=["billing"])
settings = get_settings()


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing() -> PricingResponse:
    plans = []
    for plan_id, config in subscription_service.PLAN_LIMITS.items():
        limit = config["scan_limit"]
        features = [
            f"{limit} scans/month" if limit else "Unlimited scans",
            "Professional audit reports",
        ]
        if config["pdf_export"]:
            features.append("PDF report export")
        if config.get("sbom_export"):
            features.append("CycloneDX SBOM export")
        if config["deep_audit"]:
            features.append("AI Deep Audit")
        if config["private_repos"]:
            features.append("Private repo support")
        if plan_id == "team":
            features.append("Up to 5 team members")
        upload_mb, max_files = subscription_service.upload_limits_for_plan(plan_id)
        features.append(f"Up to {upload_mb}MB project uploads")
        features.append(f"Up to {max_files:,} files per upload")

        plans.append(
            PricingPlan(
                id=plan_id,
                label=config["label"],
                price_display=config["price_display"],
                scan_limit=limit,
                features=features,
            )
        )
    return PricingResponse(plans=plans, stripe_enabled=settings.stripe_enabled)


@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SubscriptionResponse:
    info = subscription_service.build_subscription_info(current_user)
    await db.commit()
    return SubscriptionResponse(
        plan=info["plan"],
        plan_label=info["plan_label"],
        price_display=info["price_display"],
        scans_used=info["scans_used"],
        scan_limit=info["scan_limit"],
        scans_remaining=info["scans_remaining"],
        max_upload_size_mb=info["max_upload_size_mb"],
        max_zip_files=info["max_zip_files"],
        features=PlanFeatures(**info["features"]),
        billing_period_start=info["billing_period_start"],
        has_active_subscription=info["has_active_subscription"],
        stripe_enabled=settings.stripe_enabled,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    payload: CheckoutRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CheckoutResponse:
    if not settings.stripe_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe billing is not configured yet.",
        )
    try:
        url = await stripe_service.create_checkout_session(db, current_user, payload.plan)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return CheckoutResponse(checkout_url=url)


@router.post("/portal", response_model=PortalResponse)
async def create_portal(
    current_user: Annotated[User, Depends(get_current_user)],
) -> PortalResponse:
    if not settings.stripe_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe billing is not configured yet.",
        )
    try:
        url = await stripe_service.create_portal_session(current_user)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return PortalResponse(portal_url=url)


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        await stripe_service.handle_webhook(db, payload, signature)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return {"received": True}
