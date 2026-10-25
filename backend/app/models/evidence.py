"""
Evidence Model
--------------
Stores structured, reproducible technical evidence for vulnerability verification.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(Base):
    """Reproducible technical evidence for a finding."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id: Mapped[str] = mapped_column(String(36), ForeignKey("vulnerabilities.id"), nullable=False, index=True)

    evidence_type: Mapped[str] = mapped_column(String(50), default="REQUEST_RESPONSE")  # REQUEST_RESPONSE, TOKEN_ANALYSIS, HEADER_CHECK, TIMING
    
    # Baseline / Original Request & Response
    original_request: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # {method, url, headers, body}
    original_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    original_response_excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Test / Attack Request & Response
    test_request: Mapped[dict] = mapped_column(JSON, default=dict)
    test_status: Mapped[int] = mapped_column(Integer, nullable=False)
    test_response_excerpt: Mapped[str] = mapped_column(Text, nullable=False)

    observation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="HIGH")

    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationship
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability", back_populates="evidence_items")
