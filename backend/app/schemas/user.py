from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: UUID
    clerk_id: str
    email: EmailStr
    first_name: str | None
    last_name: str | None
    avatar_url: str | None
    github_pat_configured: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None


class GithubPatUpdate(BaseModel):
    github_pat: str | None = Field(default=None, max_length=500)
