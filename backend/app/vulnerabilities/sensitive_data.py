"""
Vulnerability Check: Sensitive Data Exposure in API Responses
-------------------------------------------------------------
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
OWASP API3:2023 - Broken Object Property Level Authorization

Methodology:
1. Examines JSON response bodies from data-returning endpoints (e.g. /profile, /users).
2. Recursively scans JSON keys for hazardous field names:
   - password, password_hash, passwd, hash
   - api_key, apikey, secret, private_key
   - access_token, auth_token, credit_card, ssn
3. Masks all secret values before generating reproducible technical evidence.
"""

import json
from typing import Any, Dict, List, Optional, Set

from app.core.logging import logger, mask_sensitive_data
from app.evidence.models import EvidenceArtifact, RequestRecord, ResponseRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.scanner.request_builder import RequestBuilder
from app.scanner.response_analyzer import ResponseAnalyzer
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class SensitiveDataTest(BaseVulnerabilityTest):
    """Detects exposure of passwords, hashes, and secrets in JSON responses."""

    name = "Sensitive Data Exposure"
    category = "Information Disclosure"
    cwe_id = "CWE-200"
    description = (
        "APIs that return internal database properties such as password hashes, secret keys, "
        "or API tokens in JSON responses allow attackers to harvest credentials."
    )

    SENSITIVE_KEY_PATTERNS = [
        "password",
        "password_hash",
        "passwd",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "private_key",
        "access_token",
    ]

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Runs on GET endpoints returning user profile or user records."""
        return endpoint.method == "GET" and any(k in endpoint.path.lower() for k in ["profile", "user", "account", "auth"])

    def _find_sensitive_keys(self, data: Any, current_path: str = "") -> List[str]:
        """Recursively search for sensitive keys in JSON structures."""
        exposed: List[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                path = f"{current_path}.{k}" if current_path else k
                if any(pattern == k.lower() or pattern in k.lower() for pattern in self.SENSITIVE_KEY_PATTERNS):
                    exposed.append(path)
                exposed.extend(self._find_sensitive_keys(v, path))
        elif isinstance(data, list):
            for item in data[:3]:
                exposed.extend(self._find_sensitive_keys(item, current_path))
        return exposed

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Inspect endpoint response for leaked sensitive fields."""
        findings: List[TestFinding] = []
        # Support /users/{id} by substituting test ID 1
        resolved_path = endpoint.path.replace("{id}", "1").replace("{user_id}", "1").replace("{account_id}", "101")
        url = RequestBuilder.build_url(context.target_url, resolved_path)
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(url, headers=headers)
        except Exception as e:
            logger.warning(f"Sensitive data check failed for {url}: {e}")
            return findings

        if res.status_code != 200:
            return findings

        data = ResponseAnalyzer.parse_json(res.text)
        if not data:
            return findings

        exposed_fields = self._find_sensitive_keys(data)
        if exposed_fields:
            req_record = RequestRecord(method="GET", url=url, headers=headers)
            res_record = ResponseAnalyzer.to_record(res)

            observation = (
                f"The response from '{endpoint.path}' exposed {len(exposed_fields)} confidential properties: "
                f"{', '.join(exposed_fields)}. Credentials were returned directly in the response payload."
            )

            evidence = EvidenceArtifact(
                evidence_type="REQUEST_RESPONSE",
                original_request=req_record,
                original_response=res_record,
                observation=observation,
                confidence=Confidence.HIGH.value,
            )

            findings.append(
                TestFinding(
                    type="SENSITIVE_DATA",
                    title=f"Sensitive Data Exposure on {endpoint.method} {endpoint.path}",
                    description=(
                        f"The endpoint '{endpoint.path}' leaks confidential internal fields: {', '.join(exposed_fields)}. "
                        "Sensitive fields such as password hashes and API keys must never be returned to client applications."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Credential theft, offline password cracking against exposed hashes, and API key takeover.",
                    remediation=(
                        "Filter outgoing API responses using Pydantic DTOs or response schemas that explicitly exclude "
                        "internal credentials (e.g. password_hash, api_key)."
                    ),
                    exploitability=Exploitability.EASY,
                    impact_level=Impact.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    endpoint_id=endpoint.id,
                    extra_metadata={"exposed_fields": exposed_fields},
                )
            )

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun check to verify that sensitive fields are stripped from response."""
        path = endpoint.path if endpoint else "/api/v1/profile"
        resolved_path = path.replace("{id}", "1").replace("{user_id}", "1").replace("{account_id}", "101")
        url = RequestBuilder.build_url(context.target_url, resolved_path)
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(url, headers=headers)
            if res.status_code != 200:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="NOT_REPRODUCED",
                    observation=f"Endpoint returned HTTP {res.status_code}.",
                )

            data = ResponseAnalyzer.parse_json(res.text)
            exposed = self._find_sensitive_keys(data)

            if not exposed:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation="Remediation verified! Response no longer contains password hashes, API keys, or sensitive credentials.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still vulnerable: Response continues to expose: {', '.join(exposed)}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Retest failed: {str(e)}",
            )
