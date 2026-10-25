"""
Evidence API Routes
-------------------
Endpoints to retrieve standalone reproducible evidence records.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.schemas.evidence import EvidenceResponse
from app.models.evidence import Evidence

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence"])


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve a single evidence item with full original/test requests and responses."""
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found",
        )
    return ev
