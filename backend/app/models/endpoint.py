"""
Discovered Endpoint Model
-------------------------
Stores analyzed REST API endpoints discovered via OpenAPI or probing.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DiscoveredEndpoint(Base):
    """Represents a discovered API endpoint."""

    __tablename__ = "discovered_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    method: Mapped[str] = mapped_column(String(10), nullable=False)  # GET, POST, PUT, DELETE, PATCH
    path: Mapped[str] = mapped_column(String(500), nullable=False)   # /api/v1/accounts/{id}
    summary: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    parameters: Mapped[dict] = mapped_column(JSON, default=dict)  # path, query, header params
    request_body_schema: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    response_schema: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_schemes: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["bearerAuth"]
    content_type: Mapped[str] = mapped_column(String(100), default="application/json")
    
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="endpoints")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="endpoint", cascade="all, delete-orphan", lazy="selectin"
    )
