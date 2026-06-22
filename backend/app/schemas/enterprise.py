from datetime import datetime
from uuid import UUID

from typing import Literal

from pydantic import BaseModel, Field


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    brand_name: str | None = None


class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    brand_name: str | None
    brand_logo_url: str | None
    owner_id: UUID
    created_at: datetime

    model_config = {"from_attributes": True}


class MemberInvite(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: str = "member"


class MemberResponse(BaseModel):
    id: UUID
    user_id: UUID | None
    role: str
    invited_email: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str


class ScheduleCreate(BaseModel):
    project_id: UUID
    frequency: Literal["weekly", "monthly"] = "weekly"


class ScheduleResponse(BaseModel):
    id: UUID
    project_id: UUID
    frequency: str
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CustomRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    pattern: str = Field(min_length=1, max_length=500)
    category: str = "security"
    severity: str = "medium"


class CustomRuleResponse(BaseModel):
    id: UUID
    name: str
    pattern: str
    category: str
    severity: str
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class WebhookUpdate(BaseModel):
    webhook_url: str | None = Field(default=None, max_length=500)
    webhook_secret: str | None = Field(default=None, max_length=255)


class NotificationSettings(BaseModel):
    email_alerts_enabled: bool


class IssueDismissRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
