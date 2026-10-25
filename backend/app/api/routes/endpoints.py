"""
Endpoints API Routes
--------------------
Allows inspecting all discovered endpoints for a given scan.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.schemas.endpoint import DiscoveredEndpointResponse
from app.models.endpoint import DiscoveredEndpoint

router = APIRouter(prefix="/api/v1/endpoints", tags=["Endpoints"])


@router.get("", response_model=List[DiscoveredEndpointResponse])
def list_endpoints(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Retrieve discovered endpoints, optionally filtered by scan_id."""
    query = db.query(DiscoveredEndpoint)
    if scan_id:
        query = query.filter(DiscoveredEndpoint.scan_id == scan_id)

    endpoints = query.order_by(DiscoveredEndpoint.path.asc()).offset(skip).limit(limit).all()
    return endpoints


@router.get("/{endpoint_id}", response_model=DiscoveredEndpointResponse)
def get_endpoint(
    endpoint_id: str,
    db: Session = Depends(get_db),
):
    """Get single discovered endpoint by ID."""
    endpoint = db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with ID '{endpoint_id}' not found",
        )
    return endpoint
