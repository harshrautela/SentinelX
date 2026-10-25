"""
Discovery Data Transfer Models
------------------------------
Lightweight Pydantic/dataclass models used during the discovery phase.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParameterInfo(BaseModel):
    """Parameter definition extracted from OpenAPI spec."""
    name: str
    location: str  # path, query, header, cookie
    required: bool = False
    param_type: str = "string"  # integer, string, boolean, etc.
    description: Optional[str] = None
    default_value: Optional[Any] = None
    example: Optional[Any] = None


class DiscoveredEndpointDTO(BaseModel):
    """Endpoint transfer object extracted during discovery."""
    method: str
    path: str
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[ParameterInfo] = Field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    auth_required: bool = False
    auth_schemes: List[str] = Field(default_factory=list)
    content_type: str = "application/json"
    tags: List[str] = Field(default_factory=list)

    @property
    def path_parameters(self) -> List[ParameterInfo]:
        """Return only path parameters (e.g. {id})."""
        return [p for p in self.parameters if p.location == "path"]

    @property
    def query_parameters(self) -> List[ParameterInfo]:
        """Return only query parameters."""
        return [p for p in self.parameters if p.location == "query"]
