"""
API Routes Package
"""

from app.api.routes.scans import router as scans_router
from app.api.routes.endpoints import router as endpoints_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.reports import router as reports_router

__all__ = [
    "scans_router",
    "endpoints_router",
    "vulnerabilities_router",
    "evidence_router",
    "reports_router",
]
