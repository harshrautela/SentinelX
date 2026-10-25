"""
╔══════════════════════════════════════════════════════════════════╗
║  VulnBank API — Deliberately Vulnerable Banking Application    ║
║                                                                  ║
║  ⚠️  WARNING: INTENTIONALLY VULNERABLE                          ║
║  This application contains deliberate security vulnerabilities   ║
║  for authorized VAPT testing with SentinelX.                     ║
║                                                                  ║
║  DO NOT:                                                         ║
║  - Deploy to production                                          ║
║  - Expose to the internet                                        ║
║  - Use with real user data                                       ║
║                                                                  ║
║  Set VULNBANK_SECURE_MODE=true to patch all vulnerabilities.     ║
╚══════════════════════════════════════════════════════════════════╝

Intentional Vulnerabilities:
1. BOLA/IDOR on /users/{id}, /accounts/{id}, /accounts/{id}/transactions
2. Missing authentication on /admin/users
3. JWT weaknesses (no expiration, sensitive data in claims)
4. SQL injection on /search
5. Sensitive data exposure on /profile
6. Missing security headers
7. No rate limiting on /change-password
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .routes import accounts, admin, auth, password, profile, search, users


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    yield


app = FastAPI(
    title="VulnBank API",
    description=(
        "⚠️ INTENTIONALLY VULNERABLE banking API for authorized security testing. "
        "DO NOT expose publicly."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# --- CORS (permissive for testing) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Security Headers Middleware ---
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    VULNERABLE MODE: No security headers added.
    SECURE MODE: Adds standard security headers.
    """
    response: Response = await call_next(request)

    if settings.secure_mode:
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # VULNERABLE: no security headers in default mode

    return response


# --- Register Routes ---
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(accounts.router)
app.include_router(admin.router)
app.include_router(profile.router)
app.include_router(search.router)
app.include_router(password.router)


# --- Health Check ---
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint for Docker and monitoring."""
    return {
        "status": "healthy",
        "service": "vulnbank-api",
        "secure_mode": settings.secure_mode,
        "warning": "INTENTIONALLY VULNERABLE — authorized testing only",
    }


@app.get("/", tags=["Root"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "VulnBank API",
        "version": "1.0.0",
        "warning": "⚠️ INTENTIONALLY VULNERABLE — for authorized testing only",
        "secure_mode": settings.secure_mode,
        "docs": "/docs",
        "openapi": "/openapi.json",
        "endpoints": {
            "auth": "/api/v1/auth/login",
            "users": "/api/v1/users/{id}",
            "accounts": "/api/v1/accounts/{id}",
            "transactions": "/api/v1/accounts/{id}/transactions",
            "transfer": "/api/v1/accounts/transfer",
            "admin": "/api/v1/admin/users",
            "profile": "/api/v1/profile",
            "search": "/api/v1/search?q=",
            "change_password": "/api/v1/change-password",
        },
    }
