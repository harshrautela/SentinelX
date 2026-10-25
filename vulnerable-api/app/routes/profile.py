"""
VulnBank Profile Routes
-----------------------
GET /api/v1/profile — Get current user's full profile

⚠️  VULNERABILITY: SENSITIVE DATA EXPOSURE
Returns password_hash and api_key in the JSON response.
In secure mode, these fields are excluded.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_auth
from ..config import settings
from ..database import get_db
from ..models import User
from ..schemas import UserProfileResponse, UserResponse

router = APIRouter(prefix="/api/v1", tags=["Profile"])


@router.get("/profile")
def get_profile(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_auth),
):
    """
    Get the current authenticated user's profile.

    VULNERABLE MODE: Returns password_hash and api_key.
    SECURE MODE: Returns only safe fields.
    """
    user_id = int(current_user["sub"])
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if settings.secure_mode:
        # SECURE: return only safe fields
        return UserResponse.model_validate(user)
    else:
        # VULNERABLE: return everything including password_hash and api_key
        return UserProfileResponse.model_validate(user)
