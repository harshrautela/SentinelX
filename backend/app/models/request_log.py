"""
Request Log Model
-----------------
Maintains an audit trail of every HTTP request sent during scanning.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RequestLog(Base):
    """Audit log entry for a scanner HTTP request."""

    __tablename__ = "request_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovered_endpoints.id"), nullable=True)

    method: Mapped[str] = mapped_column(String(10), nullable=False)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time_ms: Mapped[float] = mapped_column(Float, default=0.0)

    test_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="request_logs")
