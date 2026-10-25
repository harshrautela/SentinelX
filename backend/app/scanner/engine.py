"""
SentinelX Scanning Engine
-------------------------
Core orchestration engine for running VAPT scans and retests.
Coordinates discovery, authentication, test execution, evidence collection,
severity calculation, and report generation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.database import SessionLocal
from app.core.logging import logger
from app.discovery.discovery_engine import DiscoveryEngine
from app.evidence.collector import EvidenceCollector
from app.models.endpoint import DiscoveredEndpoint
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.reporting.report_generator import ReportGenerator
from app.risk.severity import SeverityCalculator
from app.scanner.request_builder import RequestBuilder
from app.vulnerabilities.base import RetestResult, ScanContext
from app.vulnerabilities.registry import VulnerabilityRegistry


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanEngine:
    """Manages execution of vulnerability tests and retest workflows."""

    def __init__(self, db: Session):
        self.db = db
        self.evidence_collector = EvidenceCollector(db)

    async def authenticate_target(
        self,
        target_url: str,
        http_client: httpx.AsyncClient,
        credentials: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """
        Authenticate against target API to obtain Bearer token for authorized testing.
        Uses supplied credentials or default test credentials (alice / password123).
        """
        creds = credentials or {"username": "alice", "password": "password123"}
        login_url = RequestBuilder.build_url(target_url, "/api/v1/auth/login")

        try:
            logger.info(f"Authenticating against target at {login_url}")
            res = await http_client.post(login_url, json=creds)
            if res.status_code == 200:
                data = res.json()
                token = data.get("access_token")
                if token:
                    logger.info("Successfully acquired Bearer token for scan.")
                    return token
        except Exception as e:
            logger.warning(f"Could not authenticate against {login_url}: {e}")

        return None

    async def run_scan(
        self,
        scan_id: str,
        target_url: str,
        openapi_url: Optional[str] = None,
        inline_spec: Optional[Dict[str, Any]] = None,
    ) -> Scan:
        """
        Execute full discovery and vulnerability assessment pipeline.
        """
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found")

        scan.started_at = utc_now()
        scan.status = "DISCOVERING"
        self.db.commit()

        async with httpx.AsyncClient(timeout=settings.request_timeout, verify=False) as http_client:
            # 1. API Surface Discovery
            discovery_engine = DiscoveryEngine(self.db)
            try:
                endpoints = await discovery_engine.discover_and_persist(
                    scan_id=scan.id,
                    target_url=target_url,
                    openapi_url=openapi_url,
                    inline_spec=inline_spec,
                )
            except Exception as e:
                logger.error(f"Discovery error during scan {scan_id}: {e}")
                scan.status = "FAILED"
                scan.error_message = f"Discovery failed: {str(e)}"
                scan.completed_at = utc_now()
                self.db.commit()
                return scan

            # 2. Acquire Auth Token for Authenticated Testing
            auth_token = await self.authenticate_target(target_url, http_client)

            # 3. Security Test Execution
            scan.status = "SCANNING"
            self.db.commit()

            context = ScanContext(
                scan_id=scan.id,
                target_url=target_url,
                db=self.db,
                http_client=http_client,
                auth_token=auth_token,
                all_endpoints=endpoints,
            )

            tests = VulnerabilityRegistry.get_all_tests()
            total_requests_estimate = 0

            for endpoint in endpoints:
                for test in tests:
                    if not test.is_applicable(endpoint):
                        continue

                    try:
                        logger.info(f"Running check '{test.name}' on {endpoint.method} {endpoint.path}")
                        findings = await test.run(endpoint, context)
                        total_requests_estimate += 2

                        for finding in findings:
                            # Calculate Severity
                            sev_result = SeverityCalculator.calculate(
                                exploitability=finding.exploitability,
                                impact=finding.impact_level,
                                confidence=finding.confidence,
                            )

                            # Create Vulnerability Record
                            db_vuln = Vulnerability(
                                scan_id=scan.id,
                                endpoint_id=finding.endpoint_id or endpoint.id,
                                type=finding.type,
                                title=finding.title,
                                description=finding.description,
                                severity=sev_result.severity,
                                confidence=finding.confidence.value,
                                cwe_id=finding.cwe_id,
                                status="OPEN",
                                impact=finding.impact,
                                remediation=finding.remediation,
                                severity_score=sev_result.score,
                                severity_rationale=sev_result.rationale,
                                extra_metadata=finding.extra_metadata,
                            )
                            self.db.add(db_vuln)
                            self.db.commit()
                            self.db.refresh(db_vuln)

                            # Persist Evidence
                            self.evidence_collector.persist_evidence(db_vuln.id, finding.evidence)
                            logger.info(f"Finding recorded: [{sev_result.severity}] {finding.title}")

                    except Exception as e:
                        logger.error(f"Error running check {test.name} on {endpoint.path}: {e}")
                        continue

            # 4. Finalize Scan
            scan.total_requests = total_requests_estimate
            scan.status = "COMPLETED"
            scan.completed_at = utc_now()
            self.db.commit()

            # 5. Generate Initial Reports
            try:
                report_gen = ReportGenerator(self.db)
                report_gen.generate(scan.id, format="JSON")
                report_gen.generate(scan.id, format="MARKDOWN")
            except Exception as e:
                logger.error(f"Failed to auto-generate reports for scan {scan.id}: {e}")

            logger.info(f"Scan {scan.id} completed successfully.")
            return scan

    async def retest_finding(self, finding: Vulnerability) -> RetestResult:
        """Rerun the specific test associated with a finding to verify fix."""
        scan = self.db.query(Scan).filter(Scan.id == finding.scan_id).first()
        endpoint = None
        if finding.endpoint_id:
            endpoint = self.db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.id == finding.endpoint_id).first()

        target_url = scan.target_url if scan else "http://localhost:8001"

        async with httpx.AsyncClient(timeout=settings.request_timeout, verify=False) as http_client:
            auth_token = await self.authenticate_target(target_url, http_client)
            context = ScanContext(
                scan_id=finding.scan_id,
                target_url=target_url,
                db=self.db,
                http_client=http_client,
                auth_token=auth_token,
            )

            test_instance = VulnerabilityRegistry.get_test_by_type(finding.type)
            if not test_instance:
                return RetestResult(
                    vulnerability_id=finding.id,
                    previous_status=finding.status,
                    new_status="NOT_REPRODUCED",
                    observation=f"No matching test module found for type '{finding.type}'.",
                )

            retest_res = await test_instance.retest(finding, endpoint, context)

            # Update finding status
            finding.status = retest_res.new_status
            finding.retested_at = utc_now()
            self.db.commit()

            logger.info(f"Retest for {finding.id} ({finding.type}) completed: {retest_res.previous_status} -> {retest_res.new_status}")
            return retest_res


def run_full_scan_pipeline(
    scan_id: str,
    target_url: str,
    openapi_url: Optional[str] = None,
    inline_spec: Optional[Dict[str, Any]] = None,
):
    """Entry point for background task execution of a scan."""
    import asyncio
    db = SessionLocal()
    try:
        engine = ScanEngine(db)
        asyncio.run(engine.run_scan(scan_id, target_url, openapi_url, inline_spec))
    finally:
        db.close()
