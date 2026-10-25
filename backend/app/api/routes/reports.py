"""
Reports API Routes
------------------
Endpoints to retrieve generated VAPT security assessment reports.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.schemas.report import ReportResponse
from app.models.report import Report
from app.models.scan import Scan
from app.reporting.report_generator import ReportGenerator

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


@router.get("/scan/{scan_id}", response_model=ReportResponse)
def get_or_generate_report(
    scan_id: str,
    format: str = Query("JSON", description="Report format: JSON or MARKDOWN"),
    db: Session = Depends(get_db),
):
    """Retrieve or generate report for a specific scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    # Check if report already exists for format
    report = (
        db.query(Report)
        .filter(Report.scan_id == scan_id, Report.format == format.upper())
        .order_by(Report.generated_at.desc())
        .first()
    )

    if not report:
        generator = ReportGenerator(db)
        report = generator.generate(scan_id, format=format.upper())

    return report


@router.get("/scan/{scan_id}/markdown", response_class=PlainTextResponse)
def get_markdown_report(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Return markdown report directly for easy reading or saving."""
    generator = ReportGenerator(db)
    report = generator.generate(scan_id, format="MARKDOWN")
    return report.content
