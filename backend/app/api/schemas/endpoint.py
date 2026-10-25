"""
Endpoint API Schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DiscoveredEndpointResponse(BaseModel):
    """Discovered endpoint representation for dashboard."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    method: str
    path: str
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    auth_required: bool = False
    auth_schemes: List[str] = Field(default_factory=list)
    content_type: str = "application/json"
    discovered_at: datetime
