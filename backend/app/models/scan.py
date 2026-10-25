"""
Scan Model
----------
Represents a VAPT scan session against a target API.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.vulnerability import Vulnerability
    from app.models.request_log import RequestLog
    from app.models.report import Report


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class Scan(Base):
    """VAPT Scan instance."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    openapi_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="PENDING")  # PENDING, DISCOVERING, SCANNING, COMPLETED, FAILED
    
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    configuration: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    endpoints: Mapped[List["DiscoveredEndpoint"]] = relationship(
        "DiscoveredEndpoint", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    request_logs: Mapped[List["RequestLog"]] = relationship(
        "RequestLog", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
