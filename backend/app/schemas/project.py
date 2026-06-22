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
    api = "api"
    cloud = "cloud"


class CloudProvider(str, Enum):
    aws = "aws"
    azure = "azure"
    gcp = "gcp"


class AuthType(str, Enum):
    none = "none"
    bearer = "bearer"
    basic = "basic"
    cookie = "cookie"
    header = "header"


class AuthConfig(BaseModel):
    type: AuthType = AuthType.none
    token: str | None = Field(default=None, max_length=4000)
    username: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, max_length=200)
    cookies: str | None = Field(default=None, max_length=4000)
    header_name: str | None = Field(default=None, max_length=100)
    header_value: str | None = Field(default=None, max_length=2000)


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
    active_dast_enabled: bool = Field(default=False)
    browser_dast_enabled: bool = Field(default=False)
    asm_enabled: bool = Field(default=False)
    auth: AuthConfig | None = None


class ProjectCreateApi(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    api_spec_url: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)
    ownership_confirmed: bool = Field(
        description="User confirms they own or have permission to scan this API"
    )
    asm_enabled: bool = Field(default=False)
    auth: AuthConfig | None = None


class ProjectAuthUpdate(BaseModel):
    auth: AuthConfig
    active_dast_enabled: bool | None = None
    browser_dast_enabled: bool | None = None
    asm_enabled: bool | None = None


class ProjectAsmUpdate(BaseModel):
    enabled: bool
    root_domain: str | None = Field(default=None, max_length=255)


class ProjectCreateLocal(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    local_path: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)


class ProjectCreateCloud(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    cloud_provider: CloudProvider
    ownership_confirmed: bool = Field(
        description="User confirms they own or have permission to scan this cloud account"
    )
    # AWS
    aws_access_key_id: str | None = Field(default=None, max_length=128)
    aws_secret_access_key: str | None = Field(default=None, max_length=256)
    aws_region: str | None = Field(default="us-east-1", max_length=50)
    aws_session_token: str | None = Field(default=None, max_length=2000)
    # Azure
    azure_tenant_id: str | None = Field(default=None, max_length=100)
    azure_client_id: str | None = Field(default=None, max_length=100)
    azure_client_secret: str | None = Field(default=None, max_length=500)
    azure_subscription_id: str | None = Field(default=None, max_length=100)
    # GCP
    gcp_service_account_json: str | None = Field(default=None, max_length=8000)


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
    active_dast_enabled: bool = False
    browser_dast_enabled: bool = False
    api_spec_url: str | None = None
    has_auth_configured: bool = False
    asm_enabled: bool = False
    asm_root_domain: str | None = None
    cloud_provider: str | None = None
    has_cloud_configured: bool = False
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
