"""
Vulnerabilities API Routes
--------------------------
Endpoints for querying findings, inspecting technical evidence, and running retests.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.schemas.vulnerability import (
    RetestResponse,
    VulnerabilityDetailResponse,
    VulnerabilityResponse,
)
from app.core.logging import logger
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, FIXED)"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Retrieve vulnerability findings with optional filtering."""
    query = db.query(Vulnerability)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status_filter:
        query = query.filter(Vulnerability.status == status_filter.upper())

    vulns = (
        query.order_by(Vulnerability.severity_score.desc(), Vulnerability.detected_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return vulns


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetailResponse)
def get_vulnerability(
    vulnerability_id: str,
    db: Session = Depends(get_db),
):
    """Get detailed finding with all attached technical evidence."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID '{vulnerability_id}' not found",
        )
    return vuln


@router.post("/{vulnerability_id}/retest", response_model=RetestResponse)
async def retest_vulnerability(
    vulnerability_id: str,
    db: Session = Depends(get_db),
):
    """
    Rerun the specific security test that produced this finding.
    Demonstrates the complete: Find -> Remediate -> Retest -> Fixed workflow!
    """
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID '{vulnerability_id}' not found",
        )

    from app.scanner.engine import ScanEngine
    engine = ScanEngine(db)
    result = await engine.retest_finding(vuln)
    return result
