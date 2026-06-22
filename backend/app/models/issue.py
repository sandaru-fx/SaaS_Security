import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Issue(Base):
    __tablename__ = "issues"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
    )
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    fix_recommendation: Mapped[str] = mapped_column(Text)
    business_risk: Mapped[str] = mapped_column(Text, nullable=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=True)
    line_start: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    rule_id: Mapped[str] = mapped_column(String(200))
    scanner: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    extra_data: Mapped[dict] = mapped_column(JSON, nullable=True)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False)
    dismissed_reason: Mapped[str] = mapped_column(Text, nullable=True)
    dismissed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    scan = relationship("Scan", back_populates="issues")
