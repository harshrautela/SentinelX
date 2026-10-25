"""
VulnBank Accounts Routes
-------------------------
GET  /api/v1/accounts/{id}               — Get account details
GET  /api/v1/accounts/{id}/transactions   — Get account transactions
POST /api/v1/accounts/transfer            — Transfer funds

⚠️  VULNERABILITY: BOLA / IDOR
Any authenticated user can access any account by changing the ID parameter.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_auth
from ..config import settings
from ..database import get_db
from ..models import Account, Transaction
from ..schemas import (
    AccountResponse,
    TransactionResponse,
    TransferRequest,
    TransferResponse,
)

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


@router.get("/{account_id}", response_model=AccountResponse)
def get_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_auth),
):
    """
    Get bank account details by ID.

    VULNERABLE MODE: No ownership check — BOLA/IDOR.
    SECURE MODE: Only account owner or admin can access.
    """
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    if settings.secure_mode:
        auth_user_id = int(current_user["sub"])
        if account.user_id != auth_user_id and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: this account does not belong to you",
            )

    return account


@router.get("/{account_id}/transactions", response_model=list[TransactionResponse])
def get_account_transactions(
    account_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_auth),
):
    """
    Get transactions for a specific account.

    VULNERABLE MODE: No ownership check — BOLA/IDOR on transaction history.
    SECURE MODE: Only account owner can access.
    """
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    if settings.secure_mode:
        auth_user_id = int(current_user["sub"])
        if account.user_id != auth_user_id and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: this account does not belong to you",
            )

    transactions = (
        db.query(Transaction)
        .filter(Transaction.account_id == account_id)
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return transactions


@router.post("/transfer", response_model=TransferResponse)
def transfer_funds(
    request: TransferRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_auth),
):
    """
    Transfer funds between accounts.

    VULNERABLE MODE: No ownership check on source account.
    SECURE MODE: Only source account owner can initiate transfer.
    """
    from_account = db.query(Account).filter(Account.id == request.from_account_id).first()
    to_account = db.query(Account).filter(Account.id == request.to_account_id).first()

    if not from_account or not to_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both accounts not found",
        )

    if settings.secure_mode:
        auth_user_id = int(current_user["sub"])
        if from_account.user_id != auth_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: source account does not belong to you",
            )

    if request.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transfer amount must be positive",
        )

    if from_account.balance < request.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient funds",
        )

    # Perform transfer
    from_account.balance -= request.amount
    to_account.balance += request.amount

    transaction = Transaction(
        account_id=from_account.id,
        amount=-request.amount,
        transaction_type="transfer",
        description=request.description,
        recipient_account_id=to_account.id,
    )
    db.add(transaction)
    db.commit()
    db.refresh(transaction)

    return TransferResponse(
        message="Transfer successful",
        transaction_id=int(transaction.id),
        from_account_id=int(from_account.id),
        to_account_id=int(to_account.id),
        amount=float(request.amount),
    )
