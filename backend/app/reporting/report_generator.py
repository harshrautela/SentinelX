"""
SentinelX Report Generator
--------------------------
Generates professional VAPT assessment reports in structured JSON and Markdown formats.
Includes:
- Executive Summary & Risk Posture
- Scope and Target Details
- Vulnerability Statistics & Severity Breakdown
- Detailed Findings with CWE, Impact, Evidence, and Remediation
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.endpoint import DiscoveredEndpoint
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReportGenerator:
    """Produces standardized security assessment reports."""

    def __init__(self, db: Session):
        self.db = db

    def generate(self, scan_id: str, format: str = "JSON") -> Report:
        """Generate and save report for scan."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found")

        vulns = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan_id)
            .order_by(Vulnerability.severity_score.desc())
            .all()
        )

        endpoints = (
            self.db.query(DiscoveredEndpoint)
            .filter(DiscoveredEndpoint.scan_id == scan_id)
            .all()
        )

        # Statistics
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for v in vulns:
            sev = v.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        if format.upper() == "MARKDOWN":
            content = self._render_markdown(scan, endpoints, vulns, severity_counts)
        else:
            data = self._render_json_data(scan, endpoints, vulns, severity_counts)
            content = json.dumps(data, indent=2, default=str)

        report = Report(
            scan_id=scan.id,
            format=format.upper(),
            title=f"SentinelX VAPT Security Assessment Report — {scan.target_url}",
            content=content,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def _render_json_data(
        self,
        scan: Scan,
        endpoints: List[DiscoveredEndpoint],
        vulns: List[Vulnerability],
        severity_counts: Dict[str, int],
    ) -> Dict[str, Any]:
        """Compile JSON report data."""
        return {
            "report_title": f"SentinelX API VAPT Security Report",
            "generated_at": utc_now().isoformat(),
            "scan_metadata": {
                "scan_id": scan.id,
                "target_url": scan.target_url,
                "openapi_url": scan.openapi_url,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "total_endpoints_discovered": len(endpoints),
                "total_requests_executed": scan.total_requests,
            },
            "executive_summary": {
                "overall_risk": "HIGH" if (severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0) else "MEDIUM",
                "total_findings": len(vulns),
                "severity_breakdown": severity_counts,
                "summary_statement": (
                    f"Automated VAPT assessment identified {len(vulns)} security findings across {len(endpoints)} endpoints. "
                    f"Prioritize remediation for {severity_counts['CRITICAL']} Critical and {severity_counts['HIGH']} High severity findings."
                ),
            },
            "findings": [
                {
                    "id": v.id,
                    "type": v.type,
                    "title": v.title,
                    "severity": v.severity,
                    "severity_score": v.severity_score,
                    "cwe_id": v.cwe_id,
                    "status": v.status,
                    "description": v.description,
                    "impact": v.impact,
                    "remediation": v.remediation,
                    "rationale": v.severity_rationale,
                    "evidence_count": len(v.evidence_items),
                    "evidence": [
                        {
                            "type": ev.evidence_type,
                            "original_status": ev.original_status,
                            "test_status": ev.test_status,
                            "observation": ev.observation,
                            "confidence": ev.confidence,
                        }
                        for ev in v.evidence_items
                    ],
                }
                for v in vulns
            ],
            "discovered_endpoints": [
                {"method": ep.method, "path": ep.path, "auth_required": ep.auth_required}
                for ep in endpoints
            ],
        }

    def _render_markdown(
        self,
        scan: Scan,
        endpoints: List[DiscoveredEndpoint],
        vulns: List[Vulnerability],
        severity_counts: Dict[str, int],
    ) -> str:
        """Render markdown report."""
        lines = [
            "# SentinelX — Automated API VAPT Security Assessment Report",
            "",
            "> **CONFIDENTIAL** — For authorized security review and remediation planning only.",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Target API:** `{scan.target_url}`",
            f"- **Scan Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Endpoints Evaluated:** {len(endpoints)}",
            f"- **Total Security Findings:** {len(vulns)}",
            "",
            "### Severity Breakdown",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| **CRITICAL** | {severity_counts['CRITICAL']} |",
            f"| **HIGH** | {severity_counts['HIGH']} |",
            f"| **MEDIUM** | {severity_counts['MEDIUM']} |",
            f"| **LOW** | {severity_counts['LOW']} |",
            f"| **INFORMATIONAL** | {severity_counts['INFO']} |",
            "",
            "## 2. Methodology & Scope",
            "",
            "SentinelX performed automated endpoint discovery, parameter fuzzing, differential response comparison, "
            "and evidence verification adhering to OWASP API Security Top 10 guidelines.",
            "",
            "## 3. Detailed Vulnerability Findings",
            "",
        ]

        if not vulns:
            lines.append("No security vulnerabilities detected during this assessment.")
        else:
            for idx, v in enumerate(vulns, 1):
                lines.extend([
                    f"### Finding #{idx}: {v.title}",
                    "",
                    f"- **Severity:** `{v.severity}` (Score: {v.severity_score}/10.0)",
                    f"- **Status:** `{v.status}`",
                    f"- **CWE:** {v.cwe_id or 'N/A'}",
                    f"- **Category:** {v.type}",
                    "",
                    "#### Description",
                    v.description,
                    "",
                    "#### Impact",
                    v.impact,
                    "",
                    "#### Reproducible Evidence",
                ])

                for ev in v.evidence_items:
                    lines.append(f"> **Observation:** {ev.observation}")
                    if ev.test_request:
                        lines.extend([
                            "",
                            "```http",
                            f"{ev.test_request.get('method')} {ev.test_request.get('url')}",
                            "```",
                        ])
                    if ev.test_response_excerpt:
                        lines.extend([
                            "",
                            "**Response Excerpt:**",
                            "```json",
                            ev.test_response_excerpt[:500],
                            "```",
                        ])

                lines.extend([
                    "",
                    "#### Remediation",
                    v.remediation,
                    "",
                    "---",
                    "",
                ])

        lines.extend([
            "## 4. Discovered API Surface",
            "",
            "| Method | Path | Authentication Required |",
            "|---|---|---|",
        ])
        for ep in endpoints:
            lines.append(f"| `{ep.method}` | `{ep.path}` | {'Yes' if ep.auth_required else 'No'} |")

        lines.extend([
            "",
            "---",
            "*Report generated automatically by SentinelX VAPT Platform.*",
        ])

        return "\n".join(lines)
