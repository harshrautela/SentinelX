"""
Evidence Collector Data Structures
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RequestRecord:
    """Captured request details."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class ResponseRecord:
    """Captured response details."""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class EvidenceArtifact:
    """Complete evidence bundle for a vulnerability finding."""
    evidence_type: str = "REQUEST_RESPONSE"
    original_request: Optional[RequestRecord] = None
    original_response: Optional[ResponseRecord] = None
    test_request: Optional[RequestRecord] = None
    test_response: Optional[ResponseRecord] = None
    observation: str = ""
    confidence: str = "HIGH"
