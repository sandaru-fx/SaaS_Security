import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="queued")
    scanners_used: Mapped[str] = mapped_column(Text, nullable=True)
    total_issues: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    health_score: Mapped[int] = mapped_column(Integer, nullable=True)
    security_score: Mapped[int] = mapped_column(Integer, nullable=True)
    architecture_score: Mapped[int] = mapped_column(Integer, nullable=True)
    performance_score: Mapped[int] = mapped_column(Integer, nullable=True)
    quality_score: Mapped[int] = mapped_column(Integer, nullable=True)
    devops_score: Mapped[int] = mapped_column(Integer, nullable=True)
    grade: Mapped[str] = mapped_column(String(2), nullable=True)
    ai_summary: Mapped[str] = mapped_column(Text, nullable=True)
    ai_business_risk: Mapped[str] = mapped_column(Text, nullable=True)
    ai_recommendations: Mapped[str] = mapped_column(Text, nullable=True)
    ai_provider: Mapped[str] = mapped_column(String(20), nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    project = relationship("Project", back_populates="scans")
    issues = relationship("Issue", back_populates="scan", cascade="all, delete-orphan")
