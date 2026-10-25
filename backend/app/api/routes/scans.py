"""
Scans API Routes
----------------
Endpoints for initiating, listing, and inspecting VAPT scans.
"""

from typing import List
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.schemas.scan import ScanCreateRequest, ScanDetailResponse, ScanResponse
from app.core.logging import logger
from app.core.security import validate_target_url
from app.discovery.discovery_engine import DiscoveryEngine
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Create a new VAPT scan session and kick off discovery in background.
    """
    # 1. SSRF prevention / URL validation
    is_valid, err_msg = validate_target_url(request.target_url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL validation failed: {err_msg}",
        )

    # 2. Create scan record
    scan = Scan(
        target_url=request.target_url,
        openapi_url=request.openapi_url,
        status="PENDING",
        configuration=request.configuration or {},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 3. Queue discovery and scanning task
    # Background execution keeps the API responsive
    from app.scanner.engine import run_full_scan_pipeline
    background_tasks.add_task(
        run_full_scan_pipeline,
        scan_id=scan.id,
        target_url=scan.target_url,
        openapi_url=scan.openapi_url,
        inline_spec=request.inline_spec,
    )

    logger.info(f"Scan created with ID {scan.id} for target {scan.target_url}")
    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """List all scans ordered by creation date descending."""
    scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return scans


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Get detailed scan status, summary stats, and vulnerability breakdown."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    # Compute severity counts
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
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

    return ScanDetailResponse(
        id=scan.id,
        target_url=scan.target_url,
        openapi_url=scan.openapi_url,
        status=scan.status,
        total_endpoints=scan.total_endpoints,
        total_requests=scan.total_requests,
        error_message=scan.error_message,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        vulnerabilities_count=len(vulns),
        severity_breakdown=severity_counts,
    )
