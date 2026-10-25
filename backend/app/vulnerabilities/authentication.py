"""
Vulnerability Check: Missing Authentication / Auth Bypass
---------------------------------------------------------
CWE-306: Missing Authentication for Critical Function
OWASP API2:2023 - Broken Authentication

Methodology:
1. Identifies endpoints marked with authentication requirements or sensitive administrative paths.
2. Sends an unauthenticated request (without Authorization header).
3. If the server returns HTTP 200 with sensitive or operational data rather than HTTP 401:
   - Verifies that critical functionality or data was accessible without credentials.
   - Compiles unauthenticated request/response as technical proof.
"""

from typing import List, Optional

from app.core.logging import logger
from app.evidence.models import EvidenceArtifact, RequestRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.scanner.request_builder import RequestBuilder
from app.scanner.response_analyzer import ResponseAnalyzer
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class AuthBypassTest(BaseVulnerabilityTest):
    """Missing Authentication / Broken Authentication test module."""

    name = "Missing Authentication"
    category = "Broken Authentication"
    cwe_id = "CWE-306"
    description = (
        "Critical API endpoints that should be restricted to authenticated users or administrators "
        "can be invoked anonymously without any credentials."
    )

    SENSITIVE_KEYWORDS = ["admin", "user", "account", "profile", "transfer", "internal", "config", "manage"]

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Applies to endpoints that either declare auth requirements or contain sensitive path terms."""
        path_lower = endpoint.path.lower()
        # Skip public auth login/register endpoints and health/docs
        if any(skip in path_lower for skip in ["/login", "/register", "/health", "/docs", "/openapi"]):
            return False

        # Applicable if auth is required or sensitive terms present
        if endpoint.auth_required:
            return True

        return any(kw in path_lower for kw in self.SENSITIVE_KEYWORDS)

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Execute unauthenticated access check."""
        findings: List[TestFinding] = []

        url = RequestBuilder.build_url(context.target_url, endpoint.path)
        # Explicitly omit Authorization header to test anonymous access
        headers = RequestBuilder.build_headers(token=None)

        try:
            res = await context.http_client.request(endpoint.method, url, headers=headers)
        except Exception as e:
            logger.warning(f"Auth check failed for {url}: {e}")
            return findings

        # Safe response: 401 Unauthorized or 403 Forbidden
        if res.status_code in (401, 403):
            return findings

        # Vulnerable behavior: HTTP 200 returned for a sensitive/admin endpoint without credentials
        if res.status_code == 200 and len(res.text) > 2:
            test_req_record = RequestRecord(method=endpoint.method, url=url, headers=headers)
            test_res_record = ResponseAnalyzer.to_record(res)

            observation = (
                f"Anonymous request without any Authorization header succeeded with HTTP 200 OK. "
                f"The server returned {len(res.text)} bytes of protected data without requiring authentication."
            )

            evidence = EvidenceArtifact(
                evidence_type="REQUEST_RESPONSE",
                test_request=test_req_record,
                test_response=test_res_record,
                observation=observation,
                confidence=Confidence.HIGH.value,
            )

            findings.append(
                TestFinding(
                    type="AUTH_BYPASS",
                    title=f"Missing Authentication on {endpoint.method} {endpoint.path}",
                    description=(
                        f"The endpoint '{endpoint.path}' failed to enforce authentication. An anonymous, "
                        f"unauthenticated client was able to invoke this endpoint and receive successful responses."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Full unauthorized access to sensitive endpoints and data by unauthenticated internet or internal actors.",
                    remediation=(
                        "Enforce strict server-side authentication middleware on this endpoint. Ensure requests without "
                        "valid bearer credentials immediately receive HTTP 401 Unauthorized."
                    ),
                    exploitability=Exploitability.EASY,
                    impact_level=Impact.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    endpoint_id=endpoint.id,
                )
            )

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun unauthenticated test to verify remediation."""
        if not endpoint:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation="Endpoint definition missing.",
            )

        url = RequestBuilder.build_url(context.target_url, endpoint.path)
        headers = RequestBuilder.build_headers(token=None)

        try:
            res = await context.http_client.request(endpoint.method, url, headers=headers)
            if res.status_code in (401, 403):
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation=f"Remediation verified! Anonymous request now blocked with HTTP {res.status_code}.",
                )
            elif res.status_code == 200:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still vulnerable: Anonymous request to {url} returned HTTP 200 OK.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="NOT_REPRODUCED",
                    observation=f"Unexpected status HTTP {res.status_code}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Retest request error: {str(e)}",
            )
