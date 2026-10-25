"""
Vulnerability Check: Broken Object Level Authorization (BOLA / IDOR)
--------------------------------------------------------------------
CWE-639: Authorization Bypass Through User-Controlled Key
OWASP API1:2023 - Broken Object Level Authorization

Methodology:
1. Identifies endpoints with path object identifiers (e.g. {id}, {account_id}, {user_id}).
2. Obtains baseline response using the authenticated user identity (e.g., ID 101 or 1).
3. Modifies the object identifier to target a different resource (e.g., ID 102 or 2)
   while retaining the original user's authentication token.
4. Analyzes the test response:
   - If HTTP 403 / 401: Server properly enforces object-level authorization (PASS).
   - If HTTP 200 with another user's resource data: BOLA vulnerability confirmed (VULNERABLE).
5. Compiles original and modified request/response pairs as reproducible evidence.
"""

import json
import re
from typing import Any, Dict, List, Optional

from app.core.logging import logger
from app.evidence.models import EvidenceArtifact, RequestRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.scanner.comparison import ResponseComparator
from app.scanner.request_builder import RequestBuilder
from app.scanner.response_analyzer import ResponseAnalyzer
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class BOLATest(BaseVulnerabilityTest):
    """BOLA / IDOR security test module."""

    name = "Broken Object Level Authorization (BOLA)"
    category = "Broken Authorization"
    cwe_id = "CWE-639"
    description = (
        "APIs that do not validate whether the currently authenticated user owns or is authorized "
        "to access the requested resource allow attackers to read, modify, or delete other users' private data."
    )

    PATH_PARAM_REGEX = re.compile(r"\{([a-zA-Z0-9_]+)\}")

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Applies to GET/PUT/DELETE endpoints that include path parameters like {id}."""
        if endpoint.method not in ("GET", "PUT", "DELETE", "PATCH"):
            return False
        return bool(self.PATH_PARAM_REGEX.search(endpoint.path))

    def _generate_test_id(self, param_name: str, baseline_id: Any) -> Any:
        """Generate alternative ID for testing BOLA."""
        try:
            val = int(baseline_id)
            # Toggle between common test IDs: 1 -> 2, 101 -> 102
            if val == 1:
                return 2
            elif val == 101:
                return 102
            elif val == 2:
                return 1
            elif val == 102:
                return 101
            else:
                return val + 1
        except (ValueError, TypeError):
            if str(baseline_id).lower() == "alice":
                return "bob"
            return "2"

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Execute BOLA testing against endpoint."""
        findings: List[TestFinding] = []
        path_params = self.PATH_PARAM_REGEX.findall(endpoint.path)
        if not path_params:
            return findings

        primary_param = path_params[0]
        # Common baseline IDs for banking/user resources
        baseline_id = 101 if "account" in endpoint.path else 1
        test_id = self._generate_test_id(primary_param, baseline_id)

        # 1. Baseline Request (with authenticated user token)
        base_url = RequestBuilder.build_url(context.target_url, endpoint.path, {primary_param: baseline_id})
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            base_res = await context.http_client.get(base_url, headers=headers)
        except Exception as e:
            logger.warning(f"BOLA baseline request failed for {base_url}: {e}")
            return findings

        # If baseline isn't accessible, try baseline_id=1
        if base_res.status_code != 200:
            baseline_id = 1
            test_id = 2
            base_url = RequestBuilder.build_url(context.target_url, endpoint.path, {primary_param: baseline_id})
            try:
                base_res = await context.http_client.get(base_url, headers=headers)
            except Exception:
                return findings

        base_record = ResponseAnalyzer.to_record(base_res)
        base_req_record = RequestRecord(method=endpoint.method, url=base_url, headers=headers)

        # 2. Test Request: Target different resource ID using original user's token
        test_url = RequestBuilder.build_url(context.target_url, endpoint.path, {primary_param: test_id})
        try:
            test_res = await context.http_client.get(test_url, headers=headers)
        except Exception as e:
            logger.warning(f"BOLA test request failed for {test_url}: {e}")
            return findings

        test_record = ResponseAnalyzer.to_record(test_res)
        test_req_record = RequestRecord(method=endpoint.method, url=test_url, headers=headers)

        # 3. Analyze authorization behavior
        # Safe response: 403 Forbidden or 401 Unauthorized
        if test_res.status_code in (403, 401):
            logger.info(f"Endpoint {endpoint.path} safely rejected foreign ID {test_id} (HTTP {test_res.status_code}).")
            return findings

        # Vulnerable behavior: HTTP 200 returned for a foreign user's object
        if test_res.status_code == 200:
            comparison = ResponseComparator.compare(base_record, test_record)

            confidence = Confidence.HIGH if comparison.semantic_ownership_different else Confidence.MEDIUM
            observation = (
                f"Authenticated request to {primary_param}={baseline_id} succeeded with HTTP 200. "
                f"Requesting foreign resource {primary_param}={test_id} with the same credentials also succeeded with HTTP 200. "
                f"{comparison.observation} No server-side ownership verification was enforced."
            )

            evidence = EvidenceArtifact(
                evidence_type="REQUEST_RESPONSE",
                original_request=base_req_record,
                original_response=base_record,
                test_request=test_req_record,
                test_response=test_record,
                observation=observation,
                confidence=confidence.value,
            )

            findings.append(
                TestFinding(
                    type="BOLA",
                    title=f"Broken Object Level Authorization on {endpoint.method} {endpoint.path}",
                    description=(
                        f"The endpoint '{endpoint.path}' allows an authenticated client to access arbitrary "
                        f"resources by manipulating the path parameter '{primary_param}'. The application failed "
                        f"to verify that the requesting user possesses authorization to view resource {test_id}."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Unauthorized disclosure or modification of another customer's private account or transaction records.",
                    remediation=(
                        "Implement strict server-side object ownership checks. Validate that the authenticated identity "
                        "(e.g. from validated JWT claims) owns or has explicit permission to access the requested resource ID."
                    ),
                    exploitability=Exploitability.EASY,
                    impact_level=Impact.HIGH,
                    confidence=confidence,
                    evidence=evidence,
                    endpoint_id=endpoint.id,
                    extra_metadata={
                        "param_name": primary_param,
                        "baseline_id": baseline_id,
                        "test_id": test_id,
                    },
                )
            )

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun BOLA test to verify remediation."""
        if not endpoint:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation="Target endpoint definition not available for retest.",
            )

        meta = finding.extra_metadata or {}
        primary_param = meta.get("param_name", "id")
        test_id = meta.get("test_id", 102)

        test_url = RequestBuilder.build_url(context.target_url, endpoint.path, {primary_param: test_id})
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(test_url, headers=headers)
            if res.status_code in (403, 401):
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation=f"Remediation verified! Foreign resource request returned HTTP {res.status_code} Forbidden.",
                )
            elif res.status_code == 200:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still vulnerable: Foreign resource request to {test_url} returned HTTP 200 OK.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="NOT_REPRODUCED",
                    observation=f"Inconclusive response code HTTP {res.status_code}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Retest request failed: {str(e)}",
            )
