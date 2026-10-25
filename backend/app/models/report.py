"""
Report Model
------------
Stores generated security assessment reports.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Report(Base):
    """Generated security report."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    format: Mapped[str] = mapped_column(String(20), default="JSON")  # JSON, MARKDOWN, HTML
    title: Mapped[str] = mapped_column(String(200), default="SentinelX Security Assessment Report")
    content: Mapped[str] = mapped_column(Text, nullable=False)

    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")
