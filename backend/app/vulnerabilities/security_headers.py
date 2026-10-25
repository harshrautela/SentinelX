"""
Vulnerability Check: Missing Security Headers
---------------------------------------------
CWE-693: Protection Mechanism Failure

Methodology:
1. Inspects HTTP response headers on baseline requests.
2. Identifies absence of modern defensive HTTP headers:
   - Content-Security-Policy
   - Strict-Transport-Security (HSTS)
   - X-Content-Type-Options
   - X-Frame-Options
3. Assigns appropriate, proportionate severity (Medium / Low) with actionable remediation.
"""

from typing import Dict, List, Optional

from app.core.logging import logger
from app.evidence.models import EvidenceArtifact, RequestRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.scanner.request_builder import RequestBuilder
from app.scanner.response_analyzer import ResponseAnalyzer
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class SecurityHeadersTest(BaseVulnerabilityTest):
    """Checks for missing HTTP defensive security headers."""

    name = "Missing Security Headers"
    category = "Security Misconfiguration"
    cwe_id = "CWE-693"
    description = (
        "HTTP security headers provide defense-in-depth against client-side attacks such as "
        "clickjacking, MIME confusion, and cross-site scripting."
    )

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": (
            "Content-Security-Policy restricts resource loading origins, mitigating XSS and data injection attacks.",
            Impact.MEDIUM,
            "default-src 'self'",
        ),
        "Strict-Transport-Security": (
            "HSTS enforces secure HTTPS connections and prevents SSL stripping attacks.",
            Impact.MEDIUM,
            "max-age=31536000; includeSubDomains",
        ),
        "X-Frame-Options": (
            "X-Frame-Options protects users against clickjacking attacks by preventing page embedding in iframes.",
            Impact.MEDIUM,
            "DENY",
        ),
        "X-Content-Type-Options": (
            "X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing response payloads.",
            Impact.LOW,
            "nosniff",
        ),
    }

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Run on profile GET endpoint to verify API response security headers."""
        return endpoint.method == "GET" and endpoint.path == "/api/v1/profile"

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Inspect headers on target endpoint."""
        findings: List[TestFinding] = []
        url = RequestBuilder.build_url(context.target_url, endpoint.path)
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(url, headers=headers)
        except Exception as e:
            logger.warning(f"Headers check failed for {url}: {e}")
            return findings

        resp_headers = {k.lower(): v for k, v in res.headers.items()}
        missing_headers: List[str] = []

        for h_name, (desc, imp, rec_val) in self.RECOMMENDED_HEADERS.items():
            if h_name.lower() not in resp_headers:
                missing_headers.append(h_name)

        if missing_headers:
            req_record = RequestRecord(method="GET", url=url, headers=headers)
            res_record = ResponseAnalyzer.to_record(res)

            observation = (
                f"The response from '{endpoint.path}' omitted the following recommended security headers: "
                f"{', '.join(missing_headers)}."
            )

            evidence = EvidenceArtifact(
                evidence_type="HEADER_CHECK",
                test_request=req_record,
                test_response=res_record,
                observation=observation,
                confidence=Confidence.HIGH.value,
            )

            findings.append(
                TestFinding(
                    type="HEADERS",
                    title=f"Missing Defensive Security Headers on {endpoint.path}",
                    description=(
                        f"The server failed to supply standard HTTP security headers: {', '.join(missing_headers)}. "
                        "Without these headers, clients may be vulnerable to MIME sniffing, framing, and browser-level downgrades."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Increased risk of client-side vulnerabilities, clickjacking, and MIME confusion.",
                    remediation=(
                        "Configure web server or FastAPI middleware to include the recommended headers: "
                        + ", ".join([f"{h}: {self.RECOMMENDED_HEADERS[h][2]}" for h in missing_headers])
                    ),
                    exploitability=Exploitability.DIFFICULT,
                    impact_level=Impact.MEDIUM if "Content-Security-Policy" in missing_headers else Impact.LOW,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    endpoint_id=endpoint.id,
                    extra_metadata={"missing_headers": missing_headers},
                )
            )

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun check to see if missing headers are now delivered."""
        path = endpoint.path if endpoint else "/health"
        url = RequestBuilder.build_url(context.target_url, path)
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(url, headers=headers)
            resp_headers = {k.lower(): v for k, v in res.headers.items()}

            meta = finding.extra_metadata or {}
            originally_missing = meta.get("missing_headers", ["Content-Security-Policy"])
            still_missing = [h for h in originally_missing if h.lower() not in resp_headers]

            if not still_missing:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation="Remediation verified! All previously missing security headers are now present in response.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still missing headers: {', '.join(still_missing)}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Retest failed: {str(e)}",
            )
