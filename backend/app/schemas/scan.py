from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel


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
    file_path: str | None
    line_start: int
    line_end: int
    rule_id: str
    scanner: str
    confidence: str
    created_at: datetime

    model_config = {"from_attributes": True}


class IssueListResponse(BaseModel):
    issues: list[IssueResponse]
    total: int
