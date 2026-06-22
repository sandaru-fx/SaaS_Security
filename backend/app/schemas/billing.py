from datetime import datetime
from uuid import UUID

from typing import Literal

from pydantic import BaseModel, Field


class PlanFeatures(BaseModel):
    pdf_export: bool
    sbom_export: bool = False
    deep_audit: bool
    private_repos: bool
    unlimited_scans: bool


class SubscriptionResponse(BaseModel):
    plan: str
    plan_label: str
    price_display: str
    scans_used: int
    scan_limit: int | None
    scans_remaining: int | None
    features: PlanFeatures
    billing_period_start: datetime | None
    has_active_subscription: bool
    stripe_enabled: bool


class CheckoutRequest(BaseModel):
    plan: Literal["pro", "team"]


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


class PricingPlan(BaseModel):
    id: str
    label: str
    price_display: str
    scan_limit: int | None
    features: list[str]


class PricingResponse(BaseModel):
    plans: list[PricingPlan]
    stripe_enabled: bool
