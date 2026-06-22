from datetime import datetime
from enum import Enum
from uuid import UUID

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
    created_at: datetime

    model_config = {"from_attributes": True}


class IssueListResponse(BaseModel):
    issues: list[IssueResponse]
    total: int


class CategoryScoreResponse(BaseModel):
    category: str
    score: int
    issue_count: int


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
    production_ready: bool
    estimated_score_if_top_fixed: int | None = Field(
        default=None,
        description="Estimated score if top 5 critical/high issues are resolved",
    )
    ai_summary: str | None = None
    ai_business_risk: str | None = None
    ai_recommendations: list[str] = Field(default_factory=list)
    ai_provider: str | None = None
