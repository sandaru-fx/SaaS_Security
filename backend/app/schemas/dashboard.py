from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.scan import ScanResponse


class DashboardStats(BaseModel):
    total_projects: int
    ready_projects: int
    total_scans: int
    completed_scans: int
    average_health_score: int | None = None
    best_health_score: int | None = None
    score_change: int | None = Field(
        default=None,
        description="Change between the two most recent completed scans (latest minus previous)",
    )


class RecentScanItem(BaseModel):
    scan_id: UUID
    project_id: UUID
    project_name: str
    status: str
    health_score: int | None
    grade: str | None
    total_issues: int
    critical_count: int
    created_at: datetime
    completed_at: datetime | None


class TrendPoint(BaseModel):
    scan_id: UUID
    project_id: UUID
    project_name: str
    health_score: int
    grade: str | None
    completed_at: datetime


class CategoryAverage(BaseModel):
    category: str
    score: int
    project_count: int


class ActiveScanItem(BaseModel):
    scan_id: UUID
    project_id: UUID
    project_name: str
    status: str
    created_at: datetime


class DashboardResponse(BaseModel):
    stats: DashboardStats
    recent_scans: list[RecentScanItem]
    score_trend: list[TrendPoint]
    category_averages: list[CategoryAverage]
    active_scans: list[ActiveScanItem]


class ScanCompareResponse(BaseModel):
    project_id: UUID
    base_scan: ScanResponse
    target_scan: ScanResponse
    score_delta: int | None
    issues_delta: int
    critical_delta: int
    high_delta: int
    medium_delta: int
    low_delta: int
    category_deltas: dict[str, int | None]
    improved: bool
