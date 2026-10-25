"""
Vulnerability Check: Missing or Ineffective Rate Limiting
---------------------------------------------------------
CWE-770: Allocation of Resources Without Limits or Throttling
OWASP API4:2023 - Unrestricted Resource Consumption

Methodology:
1. Targets sensitive operations (e.g. password modification, login, money transfer).
2. Sends a controlled, conservative burst of probe requests (e.g. 10 requests maximum).
3. Evaluates server responses:
   - If server returns HTTP 429 Too Many Requests or Retry-After header: Rate limiting is ENFORCED (PASS).
   - If all requests succeed without throttling: Rate limiting is ABSENT (VULNERABLE).
4. Strictly bounded to prevent Denial-of-Service against the target.
"""

import asyncio
from typing import List, Optional

from app.config import settings
from app.core.logging import logger
from app.evidence.models import EvidenceArtifact, RequestRecord, ResponseRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.scanner.request_builder import RequestBuilder
from app.scanner.response_analyzer import ResponseAnalyzer
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class RateLimitTest(BaseVulnerabilityTest):
    """Controlled rate limit testing module."""

    name = "Missing Rate Limiting"
    category = "Resource Management"
    cwe_id = "CWE-770"
    description = (
        "Sensitive endpoints lacking request throttling allow attackers to execute credential stuffing, "
        "brute-force passwords, or overwhelm application logic."
    )

    SENSITIVE_ENDPOINTS = ["password", "change-password", "login", "transfer"]

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Runs only on sensitive operational endpoints."""
        return any(term in endpoint.path.lower() for term in self.SENSITIVE_ENDPOINTS)

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Execute small, controlled burst of requests to verify throttling."""
        findings: List[TestFinding] = []
        url = RequestBuilder.build_url(context.target_url, endpoint.path)
        headers = RequestBuilder.build_headers(token=context.auth_token)

        # Safe limit (default 10 requests) to test throttling without causing DoS
        probe_count = min(10, settings.max_rate_limit_probe_requests)
        body = {"current_password": "probe_current", "new_password": "probe_new"}

        status_codes = []
        last_response = None

        for _ in range(probe_count):
            try:
                res = await context.http_client.post(url, json=body, headers=headers)
                status_codes.append(res.status_code)
                last_response = res
                if res.status_code == 429:
                    break
                await asyncio.sleep(0.05)
            except Exception as e:
                logger.warning(f"Rate limit probe error: {e}")
                break

        if not status_codes:
            return findings

        # If HTTP 429 was returned, rate limiting works!
        if 429 in status_codes:
            logger.info(f"Rate limiting properly enforced on {endpoint.path} (received HTTP 429).")
            return findings

        # Check for rate limit headers
        has_rate_limit_headers = False
        if last_response:
            has_rate_limit_headers = any(
                h.lower() in ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining")
                for h in last_response.headers.keys()
            )

        if not has_rate_limit_headers:
            req_record = RequestRecord(method=endpoint.method, url=url, headers=headers, body=body)
            res_record = ResponseAnalyzer.to_record(last_response) if last_response else ResponseRecord(status_code=200)

            observation = (
                f"Sent {len(status_codes)} rapid consecutive requests to sensitive endpoint '{endpoint.path}'. "
                f"Status codes observed: {status_codes}. No HTTP 429 Too Many Requests response or Retry-After header was returned."
            )

            evidence = EvidenceArtifact(
                evidence_type="TIMING",
                test_request=req_record,
                test_response=res_record,
                observation=observation,
                confidence=Confidence.HIGH.value,
            )

            findings.append(
                TestFinding(
                    type="RATE_LIMIT",
                    title=f"Missing Rate Limiting on {endpoint.method} {endpoint.path}",
                    description=(
                        f"The sensitive endpoint '{endpoint.path}' allows unlimited request submissions without throttling. "
                        f"All {len(status_codes)} probe requests were processed without rate limiting enforcement."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Susceptibility to brute-force credential guessing, password spraying, and resource exhaustion.",
                    remediation=(
                        "Implement IP-based and user-based rate limiting on sensitive endpoints (e.g. max 5 attempts per 5 minutes) "
                        "and return HTTP 429 with a standard Retry-After header."
                    ),
                    exploitability=Exploitability.MODERATE,
                    impact_level=Impact.MEDIUM,
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
        """Rerun burst test to see if rate limit is now active."""
        path = endpoint.path if endpoint else "/api/v1/change-password"
        url = RequestBuilder.build_url(context.target_url, path)
        headers = RequestBuilder.build_headers(token=context.auth_token)
        body = {"current_password": "test", "new_password": "test"}

        status_codes = []
        for _ in range(10):
            try:
                res = await context.http_client.post(url, json=body, headers=headers)
                status_codes.append(res.status_code)
                if res.status_code == 429:
                    return RetestResult(
                        vulnerability_id=finding.id,
                        previous_status=finding.status,
                        new_status="FIXED",
                        observation=f"Remediation verified! Server returned HTTP 429 Too Many Requests after {len(status_codes)} attempts.",
                    )
                await asyncio.sleep(0.05)
            except Exception as e:
                break

        return RetestResult(
            vulnerability_id=finding.id,
            previous_status=finding.status,
            new_status="OPEN",
            observation=f"Still vulnerable: Sent 10 requests without triggering HTTP 429.",
        )
