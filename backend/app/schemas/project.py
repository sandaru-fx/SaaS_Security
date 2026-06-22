from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    github = "github"
    zip = "zip"
    folder = "folder"
    local = "local"
    website = "website"


class ProjectStatus(str, Enum):
    pending = "pending"
    processing = "processing"
    ready = "ready"
    failed = "failed"


class ProjectCreateGithub(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    repo_url: str = Field(min_length=1, max_length=500)
    branch: str = Field(default="main", min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)


class ProjectCreateWebsite(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    website_url: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)
    ownership_confirmed: bool = Field(
        description="User confirms they own or have permission to scan this website"
    )


class ProjectCreateLocal(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    local_path: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    source_type: SourceType
    repo_url: str | None
    repo_branch: str | None
    status: ProjectStatus
    status_message: str | None
    file_count: int
    domain_verified: bool = False
    domain_verification_token: str | None = None
    pr_checks_enabled: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DomainVerificationInfo(BaseModel):
    domain: str
    token: str
    dns_record_name: str
    dns_record_value: str
    meta_tag: str
    verified: bool


class ProjectPrChecksUpdate(BaseModel):
    enabled: bool


class ProjectListResponse(BaseModel):
    projects: list[ProjectResponse]
    total: int
