"""
Report API Schemas
"""

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ReportResponse(BaseModel):
    """Generated report metadata and content."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    format: str
    title: str
    content: str
    generated_at: datetime
