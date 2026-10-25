"""
VulnBank Password Change Route
-------------------------------
POST /api/v1/change-password — Change the current user's password

⚠️  VULNERABILITY: NO RATE LIMITING
This endpoint has no throttling, allowing brute-force attacks.
In secure mode, a basic in-memory rate limiter is applied.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, DefaultDict, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..auth import require_auth
from ..config import settings
from ..database import get_db, hash_password
from ..models import User
from ..schemas import ChangePasswordRequest

router = APIRouter(prefix="/api/v1", tags=["Password"])

# Simple in-memory rate limiter for secure mode
_rate_limit_store: DefaultDict[str, List[datetime]] = defaultdict(list)
RATE_LIMIT_WINDOW = timedelta(minutes=5)
RATE_LIMIT_MAX_REQUESTS = 5


def _check_rate_limit(client_ip: str) -> bool:
    """Returns True if request is allowed, False if rate-limited."""
    now = datetime.now(timezone.utc)
    # Clean old entries safely supporting both offset-naive and aware datetimes
    cleaned: List[datetime] = []
    for ts in _rate_limit_store[client_ip]:
        aware_ts = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
        if now - aware_ts < RATE_LIMIT_WINDOW:
            cleaned.append(aware_ts)
    _rate_limit_store[client_ip] = cleaned
    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    _rate_limit_store[client_ip].append(now)
    return True


@router.post("/change-password")
def change_password(
    request_body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(require_auth),
):
    """
    Change the authenticated user's password.

    VULNERABLE MODE: No rate limiting — unlimited attempts.
    SECURE MODE: Max 5 attempts per 5 minutes per IP.
    """
    if settings.secure_mode:
        client_ip = request.client.host if request.client else "unknown"
        if not _check_rate_limit(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Try again later.",
                headers={"Retry-After": "300"},
            )

    raw_user_id = current_user.get("sub") or current_user.get("user_id")
    if not raw_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload: missing user identifier",
        )
    user_id = int(raw_user_id)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Verify current password
    if user.password_hash != hash_password(request_body.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Update password
    user.password_hash = hash_password(request_body.new_password)
    db.commit()

    return {"message": "Password changed successfully"}
