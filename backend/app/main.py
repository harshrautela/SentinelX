"""
SentinelX Backend API
=====================
Automated API VAPT & Vulnerability Intelligence Platform.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    endpoints_router,
    evidence_router,
    reports_router,
    scans_router,
    vulnerabilities_router,
)
from app.config import settings
from app.core.database import init_db
from app.core.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on application startup."""
    logger.info("Initializing SentinelX Database...")
    init_db()
    logger.info("SentinelX Platform Backend ready.")
    yield


app = FastAPI(
    title="SentinelX — API VAPT Platform",
    description=(
        "Automated API vulnerability assessment and penetration testing platform. "
        "Discovers REST APIs, performs controlled security tests, verifies findings with reproducible "
        "evidence, computes risk scores, and supports retesting after remediation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(scans_router)
app.include_router(endpoints_router)
app.include_router(vulnerabilities_router)
app.include_router(evidence_router)
app.include_router(reports_router)


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint for Docker and monitoring."""
    return {
        "status": "healthy",
        "service": "sentinelx-backend",
        "version": "1.0.0",
    }


@app.get("/", tags=["Root"])
def root():
    """SentinelX root informational endpoint."""
    return {
        "name": "SentinelX API VAPT Platform",
        "version": "1.0.0",
        "documentation": "/docs",
        "openapi": "/openapi.json",
        "modules": [
            "API Discovery Engine (OpenAPI 3.x)",
            "Broken Object Level Authorization (BOLA/IDOR)",
            "Missing Authentication / Auth Bypass",
            "Defensive Security Headers",
            "JWT Security Analysis",
            "Sensitive Data Exposure Detection",
            "Controlled SQL Injection Detection",
            "Controlled Rate Limiting Probing",
            "Evidence Collection & Sanitization",
            "Risk & Severity Scoring",
            "Assessment Reports (JSON & Markdown)",
            "Remediation Retest Engine",
        ],
    }
