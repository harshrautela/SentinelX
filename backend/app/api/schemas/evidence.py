"""
Evidence API Schemas
"""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceResponse(BaseModel):
    """Reproducible technical evidence for a finding."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    vulnerability_id: str
    evidence_type: str
    original_request: Optional[Dict[str, Any]] = None
    original_status: Optional[int] = None
    original_response_excerpt: Optional[str] = None
    test_request: Dict[str, Any] = Field(default_factory=dict)
    test_status: int
    test_response_excerpt: str
    observation: str
    confidence: str
    collected_at: datetime
