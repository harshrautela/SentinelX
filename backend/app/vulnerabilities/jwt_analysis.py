"""
Vulnerability Check: JWT Security Configuration Analysis
---------------------------------------------------------
CWE-287: Improper Authentication
CWE-326: Inadequate Encryption Strength

Methodology:
1. Obtains authentication token from login or context.
2. Inspects unverified header and payload claims:
   - Verifies whether expiration ('exp') claim is missing.
   - Detects whether sensitive attributes (api_key, password, secret) are exposed in claims.
   - Analyzes header algorithm configuration.
3. Compiles structured claims analysis as verifiable evidence (with sensitive data masked).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import jwt

from app.core.logging import logger, mask_sensitive_data
from app.evidence.models import EvidenceArtifact, RequestRecord, ResponseRecord
from app.models.endpoint import DiscoveredEndpoint
from app.models.vulnerability import Vulnerability
from app.risk.cvss import Confidence, Exploitability, Impact
from app.vulnerabilities.base import BaseVulnerabilityTest, RetestResult, ScanContext, TestFinding


class JWTAnalysisTest(BaseVulnerabilityTest):
    """Analyzes JWT tokens for configuration weaknesses and sensitive claims."""

    name = "JWT Security Weakness"
    category = "Cryptographic / Authentication"
    cwe_id = "CWE-287"
    description = (
        "Insecure JWT implementations may omit expiration timestamps, expose confidential "
        "credentials inside unencrypted claims, or rely on weak signing algorithms."
    )

    SENSITIVE_CLAIM_NAMES = ["api_key", "password", "secret", "private_key", "ssn", "credit_card"]

    def is_applicable(self, endpoint: DiscoveredEndpoint) -> bool:
        """Runs on auth endpoints that issue JWT tokens (e.g. /login)."""
        return endpoint.method == "POST" and "login" in endpoint.path.lower()

    async def run(
        self,
        endpoint: DiscoveredEndpoint,
        context: ScanContext,
    ) -> List[TestFinding]:
        """Inspect JWT token issued by the application."""
        findings: List[TestFinding] = []
        token = context.auth_token

        if not token:
            return findings

        try:
            # Decode unverified to inspect raw headers and claims
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            logger.warning(f"Failed to decode token for JWT analysis: {e}")
            return findings

        flaws: List[str] = []

        # 1. Missing Expiration ('exp')
        if "exp" not in payload:
            flaws.append("Missing token expiration ('exp' claim). Token is valid indefinitely.")

        # 2. Sensitive data in claims
        exposed_keys = [k for k in payload.keys() if any(s in k.lower() for s in self.SENSITIVE_CLAIM_NAMES)]
        if exposed_keys:
            flaws.append(f"Confidential data exposed in unencrypted claims: {', '.join(exposed_keys)}.")

        # 3. None algorithm
        if header.get("alg", "").lower() == "none":
            flaws.append("Algorithm set to 'none', allowing signature bypass.")

        if flaws:
            masked_payload = {k: mask_sensitive_data(str(v)) for k, v in payload.items()}
            observation = (
                f"JWT security analysis identified {len(flaws)} weaknesses: "
                + " | ".join(flaws)
                + f" (Header: {json.dumps(header)})"
            )

            res_record = ResponseRecord(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=f"Decoded Header: {json.dumps(header)}\nDecoded Payload: {json.dumps(masked_payload, indent=2)}",
            )

            evidence = EvidenceArtifact(
                evidence_type="TOKEN_ANALYSIS",
                test_response=res_record,
                observation=observation,
                confidence=Confidence.HIGH.value,
            )

            findings.append(
                TestFinding(
                    type="JWT",
                    title="Insecure JSON Web Token (JWT) Configuration",
                    description=(
                        "The application issues JWT tokens with security misconfigurations: "
                        + "; ".join(flaws)
                        + ". JWT claims are merely Base64-encoded and can be read by anyone possessing the token."
                    ),
                    cwe_id=self.cwe_id,
                    impact="Token replay attacks due to lack of expiration, and credential harvesting from exposed claims.",
                    remediation=(
                        "1. Always set an appropriate short-lived expiration time ('exp' claim) on access tokens.\n"
                        "2. Never place confidential secrets, private keys, or passwords inside JWT claims.\n"
                        "3. Enforce strong HMAC SHA-256 (HS256) with a minimum 256-bit secret, or RSA/ECDSA asymmetric signatures."
                    ),
                    exploitability=Exploitability.EASY,
                    impact_level=Impact.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    endpoint_id=endpoint.id,
                    extra_metadata={"flaws": flaws},
                )
            )

        return findings

    async def retest(
        self,
        finding: Vulnerability,
        endpoint: Optional[DiscoveredEndpoint],
        context: ScanContext,
    ) -> RetestResult:
        """Rerun JWT check on new token."""
        token = context.auth_token
        if not token:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation="No auth token available for retest.",
            )

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            flaws = []
            if "exp" not in payload:
                flaws.append("Missing 'exp' claim")
            exposed_keys = [k for k in payload.keys() if any(s in k.lower() for s in self.SENSITIVE_CLAIM_NAMES)]
            if exposed_keys:
                flaws.append(f"Exposed claims: {', '.join(exposed_keys)}")

            if not flaws:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="FIXED",
                    observation="Remediation verified! New token includes expiration timestamp and contains no sensitive credentials in claims.",
                )
            else:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="OPEN",
                    observation=f"Still vulnerable: {', '.join(flaws)}.",
                )
        except Exception as e:
            return RetestResult(
                vulnerability_id=finding.id,
                previous_status=finding.status,
                new_status="NOT_REPRODUCED",
                observation=f"Token parse error: {str(e)}",
            )
