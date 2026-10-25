"""
Base Vulnerability Test Interface
---------------------------------
Plugin-style architecture for all SentinelX security checks.
Every vulnerability check implements this interface, allowing checks
to be registered, executed, and retested independently.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy.orm import Session

from app.evidence.models import EvidenceArtifact
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact


@dataclass
class ScanContext:
    """Runtime context passed to vulnerability checks during scanning."""
    scan_id: str
    target_url: str
    db: Session
    http_client: httpx.AsyncClient
    auth_token: Optional[str] = None
    auth_credentials: Dict[str, Any] = field(default_factory=dict)
    all_endpoints: List[DiscoveredEndpoint] = field(default_factory=list)


@dataclass
class TestFinding:
    """Candidate vulnerability detected by a check."""
    type: str
    title: str
    description: str
    cwe_id: str
    impact: str
    remediation: str
    exploitability: Exploitability
    impact_level: Impact
    confidence: Confidence
    evidence: EvidenceArtifact
    endpoint_id: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetestResult:
    """Outcome of rerunning a test on a specific finding."""
    vulnerability_id: str
    previous_status: str
    new_status: str  # FIXED, OPEN, NOT_REPRODUCED
    observation: str


class BaseVulnerabilityTest(ABC):
    """Abstract base class for all SentinelX vulnerability modules."""

    name: str = "BaseTest"
    category: str = "General"
    cwe_id: str = "CWE-000"
    description: str = ""

    @abstractmethod
    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Return True if this check is relevant for the given endpoint."""
        pass

    @abstractmethod
    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """
        Execute the vulnerability check against the endpoint.
        Returns a list of verified findings with reproducible evidence.
        """
        pass

    @abstractmethod
    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """
        Rerun check against previously flagged finding to verify remediation.
        """
        pass
