from datetime import datetime
from enum import Enum
from uuid import UUID

from typing import Literal

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class IssueSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ScanResponse(BaseModel):
    id: UUID
    project_id: UUID
    status: ScanStatus
    scanners_used: list[str]
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    health_score: int | None = None
    security_score: int | None = None
    architecture_score: int | None = None
    performance_score: int | None = None
    quality_score: int | None = None
    devops_score: int | None = None
    grade: str | None = None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int


class IssueResponse(BaseModel):
    id: UUID
    scan_id: UUID
    category: str
    severity: IssueSeverity
    title: str
    description: str
    impact: str
    fix_recommendation: str
    business_risk: str | None = None
    file_path: str | None
    line_start: int
    line_end: int
    rule_id: str
    scanner: str
    confidence: str
    priority: int | None = None
    report_category: str | None = None
    dismissed: bool = False
    dismissed_reason: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    ai_triage_verdict: str | None = None
    ai_triage_reason: str | None = None
    ai_fix_suggestion: str | None = None
    reachable: str | None = None
    reachable_files: str | None = None
    taint_verified: bool = False
    validated: str | None = None
    validated_principal: str | None = None
    validated_method: str | None = None
    secret_preview: str | None = None
    risk_score: int | None = None
    epss_score: float | None = None
    kev_listed: bool = False
    risk_factors: str | None = None
    fix_now: bool = False
    severity_adjusted: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class IssueListResponse(BaseModel):
    issues: list[IssueResponse]
    total: int


class CategoryScoreResponse(BaseModel):
    category: str
    score: int
    issue_count: int


class ComplianceControlResponse(BaseModel):
    framework: str
    control_id: str
    title: str
    issue_count: int
    max_severity: str
    status: str


class AuditReportResponse(BaseModel):
    scan_id: UUID
    project_id: UUID
    status: ScanStatus
    overall_score: int
    grade: str
    categories: list[CategoryScoreResponse]
    severity_breakdown: dict[str, int]
    executive_summary: str
    fix_plan: list[str]
    top_priority_issues: list[IssueResponse]
    fix_now_issues: list[IssueResponse] = Field(default_factory=list)
    fix_now_count: int = 0
    max_risk_score: int | None = None
    production_ready: bool
    estimated_score_if_top_fixed: int | None = Field(
        default=None,
        description="Estimated score if top 5 critical/high issues are resolved",
    )
    ai_summary: str | None = None
    ai_business_risk: str | None = None
    ai_recommendations: list[str] = Field(default_factory=list)
    ai_provider: str | None = None
    compliance: list[ComplianceControlResponse] = Field(default_factory=list)


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class AuditChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=12)


class AuditChatResponse(BaseModel):
    reply: str
    provider: str
