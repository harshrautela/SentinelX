"""
VulnBank Admin Routes
---------------------
GET /api/v1/admin/users — List all users

⚠️  VULNERABILITY: MISSING AUTHENTICATION
This endpoint returns all user data without requiring any authentication.
In secure mode, it requires an admin-role JWT.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..config import settings
from ..database import get_db
from ..models import User
from ..schemas import UserResponse

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


@router.get("/users", response_model=list[UserResponse])
def list_all_users(
    db: Session = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
):
    """
    List all users in the system.

    VULNERABLE MODE: No authentication required at all.
    SECURE MODE: Requires admin role JWT.
    """
    if settings.secure_mode:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required",
            )

    # VULNERABLE: returns all users regardless of authentication
    users = db.query(User).all()
    return users
