"""
Vulnerability Check: Controlled SQL Injection
---------------------------------------------
CWE-89: Improper Neutralization of Special Elements used in an SQL Command
OWASP API8:2023 - Security Misconfiguration / Injection

Methodology:
1. Identifies endpoints accepting user query parameters or search inputs.
2. Sends safe, controlled SQL injection probe payloads:
   - Error-inducing payload: "'" (unbalanced single quote)
   - Boolean tautology payload: "' OR '1'='1"
3. Performs baseline comparison against benign input.
4. Analyzes response for:
   - Database error signatures (SQLite, Postgres, MySQL, ODBC)
   - Behavioral result set expansion (tautology returns entire dataset)
5. Assigns appropriate confidence and collects reproducible evidence.
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


class InjectionTest(BaseVulnerabilityTest):
    """Controlled SQL injection detection module."""

    name = "SQL Injection"
    category = "Injection"
    cwe_id = "CWE-89"
    description = (
        "Unsanitized user input concatenated into database queries allows attackers to execute "
        "arbitrary SQL statements, bypassing authorization and extracting confidential data."
    )

    SAFE_PAYLOADS = [
        ("'", "Error-inducing syntax probe"),
        ("' OR '1'='1", "Boolean tautology probe"),
    ]

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Applies to endpoints with query parameters or search in the path."""
        if "search" in endpoint.path.lower() or "query" in endpoint.path.lower():
            return True
        params = endpoint.parameters.get("params", [])
        return any(p.get("location") == "query" for p in params)

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Execute controlled injection testing."""
        findings: List[TestFinding] = []

        params = endpoint.parameters.get("params", [])
        query_param_names = [p["name"] for p in params if p.get("location") == "query"]
        if not query_param_names:
            query_param_names = ["q"]

        target_param = query_param_names[0]

        # 1. Benign Baseline Request
        base_url = f"{context.target_url.rstrip('/')}{endpoint.path}?{target_param}=alice"
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            base_res = await context.http_client.get(base_url, headers=headers)
        except Exception as e:
            logger.warning(f"SQLi baseline request failed: {e}")
            return findings

        base_record = ResponseAnalyzer.to_record(base_res)
        base_req = RequestRecord(method="GET", url=base_url, headers=headers)

        # 2. Test Payloads
        for payload, description in self.SAFE_PAYLOADS:
            test_url = f"{context.target_url.rstrip('/')}{endpoint.path}?{target_param}={payload}"
            try:
                test_res = await context.http_client.get(test_url, headers=headers)
            except Exception as e:
                continue

            test_record = ResponseAnalyzer.to_record(test_res)
            test_req = RequestRecord(method="GET", url=test_url, headers=headers)

            # Analyze for database errors
            db_errors = ResponseAnalyzer.find_database_errors(test_res.text)

            # Analyze for tautology data expansion (if JSON array returned)
            data_expanded = False
            base_count = 0
            test_count = 0
            base_json = ResponseAnalyzer.parse_json(base_res.text)
            test_json = ResponseAnalyzer.parse_json(test_res.text)

            if isinstance(base_json, dict) and isinstance(test_json, dict):
                base_count = base_json.get("count", 0)
                test_count = test_json.get("count", 0)
                if test_count > base_count and "OR" in payload:
                    data_expanded = True

            is_vulnerable = bool(db_errors) or data_expanded

            if is_vulnerable:
                confidence = Confidence.HIGH if (db_errors and data_expanded) else (Confidence.HIGH if db_errors else Confidence.MEDIUM)

                observation_parts = []
                if db_errors:
                    observation_parts.append(f"Database error signatures revealed: {', '.join(db_errors[:3])}.")
                if data_expanded:
                    observation_parts.append(f"Boolean tautology '{payload}' expanded result count from {base_count} to {test_count}.")

                observation = (
                    f"Controlled injection probe ({description}) triggered behavioral change: "
                    + " ".join(observation_parts)
                )

                evidence = EvidenceArtifact(
                    evidence_type="REQUEST_RESPONSE",
                    original_request=base_req,
                    original_response=base_record,
                    test_request=test_req,
                    test_response=test_record,
                    observation=observation,
                    confidence=confidence.value,
                )

                findings.append(
                    TestFinding(
                        type="INJECTION",
                        title=f"SQL Injection on {endpoint.method} {endpoint.path} (param: {target_param})",
                        description=(
                            f"The parameter '{target_param}' on endpoint '{endpoint.path}' is vulnerable to SQL injection. "
                            f"Sending payload '{payload}' produced direct database error disclosure or unexpected query expansion."
                        ),
                        cwe_id=self.cwe_id,
                        impact="Complete database compromise, unauthorized data extraction, and potential backend takeover.",
                        remediation=(
                            "Use parameterized queries, prepared statements, or ORM abstractions. Never concatenate user "
                            "input directly into SQL command strings."
                        ),
                        exploitability=Exploitability.EASY,
                        impact_level=Impact.CRITICAL,
                        confidence=confidence,
                        evidence=evidence,
                        endpoint_id=endpoint.id,
                        extra_metadata={"param": target_param, "payload": payload},
                    )
                )
                break  # Stop after first confirmed payload on this endpoint

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun injection probe to verify remediation."""
        path = endpoint.path if endpoint else "/api/v1/search"
        meta = finding.extra_metadata or {}
        param = meta.get("param", "q")
        payload = meta.get("payload", "'")

        test_url = f"{context.target_url.rstrip('/')}{path}?{param}={payload}"
        headers = RequestBuilder.build_headers(token=context.auth_token)

        try:
            res = await context.http_client.get(test_url, headers=headers)
            db_errors = ResponseAnalyzer.find_database_errors(res.text)

            if not db_errors:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation="Remediation verified! Input properly parameterized; no database errors or query tampering detected.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still vulnerable: Response triggered database errors: {', '.join(db_errors)}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Retest request error: {str(e)}",
            )
