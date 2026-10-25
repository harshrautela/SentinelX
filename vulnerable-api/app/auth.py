"""
VulnBank Authentication Module
-------------------------------
JWT-based authentication with INTENTIONAL weaknesses:

1. Weak secret key (hardcoded, short)
2. No token expiration in vulnerable mode
3. Sensitive user data in JWT claims (api_key)
4. MD5 password hashing

In secure mode (VULNBANK_SECURE_MODE=true):
- Token expiration is added (1 hour)
- Sensitive claims are removed
- All other fixes applied
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db, hash_password
from .models import User

# FastAPI security scheme
security_scheme = HTTPBearer(auto_error=False)


def create_access_token(user: User) -> str:
    """
    Create a JWT token for the given user.

    VULNERABLE MODE:
    - No expiration
    - Includes api_key in claims

    SECURE MODE:
    - 1-hour expiration
    - Minimal claims
    """
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
    }

    if settings.secure_mode:
        # SECURE: add expiration, minimal claims
        payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
        payload["iat"] = datetime.now(timezone.utc)
    else:
        # VULNERABLE: no expiration, sensitive data in claims
        payload["email"] = user.email
        payload["api_key"] = user.api_key  # ⚠️ Sensitive data in JWT

    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": settings.secure_mode},
        )
        return payload
    except jwt.InvalidTokenError:
        return None


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Verify credentials and return the user if valid."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if user.password_hash != hash_password(password):
        return None
    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> Optional[dict]:
    """
    Extract and validate the current user from the Authorization header.
    Returns None if no credentials provided (for optional auth endpoints).
    """
    if credentials is None:
        return None

    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def require_auth(
    current_user: Optional[dict] = Depends(get_current_user),
) -> dict:
    """
    Dependency that REQUIRES authentication.
    Raises 401 if no valid token is present.
    """
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user
