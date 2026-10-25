"""
VulnBank Pydantic Schemas
--------------------------
Request/response models for the API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


# --- Auth ---

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


# --- User ---

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    created_at: datetime


class UserProfileResponse(BaseModel):
    """
    Full user profile — INTENTIONALLY includes sensitive fields.
    In secure mode, password_hash and api_key are excluded.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    password_hash: Optional[str] = None   # VULNERABILITY: sensitive data exposure
    api_key: Optional[str] = None          # VULNERABILITY: sensitive data exposure
    created_at: datetime


# --- Account ---

class AccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    account_number: str
    balance: float
    account_type: str
    created_at: datetime


# --- Transaction ---

class TransactionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    account_id: int
    amount: float
    transaction_type: str
    description: Optional[str] = None
    recipient_account_id: Optional[int] = None
    created_at: datetime


# --- Transfer ---

class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float
    description: str = "Transfer"


class TransferResponse(BaseModel):
    message: str
    transaction_id: int
    from_account_id: int
    to_account_id: int
    amount: float


# --- Password Change ---

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# --- Search ---

class SearchResponse(BaseModel):
    query: str
    results: list
    count: int
