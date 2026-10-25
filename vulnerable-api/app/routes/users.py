"""
VulnBank Users Routes
---------------------
GET /api/v1/users/{id}  — Retrieve user details

⚠️  VULNERABILITY: BOLA / IDOR
Any authenticated user can access any other user's data by changing the ID.
No server-side ownership check is performed in vulnerable mode.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_auth
from ..config import settings
from ..database import get_db
from ..models import User
from ..schemas import UserResponse

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_auth),
):
    """
    Get user details by ID.

    VULNERABLE MODE: Any authenticated user can view any user's data.
    SECURE MODE: Users can only view their own data (or admin can view all).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if settings.secure_mode:
        # SECURE: enforce ownership or admin role
        auth_user_id = int(current_user["sub"])
        if auth_user_id != user.id and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you can only view your own profile",
            )

    # VULNERABLE: no ownership check — any authenticated user sees any user
    return user
