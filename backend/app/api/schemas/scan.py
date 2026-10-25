"""
Scan API Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    """Request payload to initiate a new API VAPT scan."""
    target_url: str = Field(..., json_schema_extra={"example": "http://localhost:8001"})
    openapi_url: Optional[str] = Field(None, json_schema_extra={"example": "http://localhost:8001/openapi.json"})
    inline_spec: Optional[Dict[str, Any]] = None
    configuration: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    """Scan details returned by SentinelX API."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    openapi_url: Optional[str] = None
    status: str
    total_endpoints: int = 0
    total_requests: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanDetailResponse(ScanResponse):
    """Detailed scan view with statistics and counts."""
    vulnerabilities_count: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
