"""
VulnBank Database Models
------------------------
SQLAlchemy ORM models for the vulnerable banking application.
"""

from datetime import datetime, timezone

from typing import Any, List

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    __allow_unmapped__ = True


class User(Base):
    """
    User model.

    Vulnerabilities present:
    - password_hash stored as MD5 (weak hashing)
    - api_key stored in plaintext
    - Both are returned in profile endpoint (sensitive data exposure)
    """

    __tablename__ = "users"

    id: Any = Column(Integer, primary_key=True, autoincrement=True)
    username: Any = Column(String(50), unique=True, nullable=False, index=True)
    email: Any = Column(String(100), unique=True, nullable=False)
    password_hash: Any = Column(String(255), nullable=False)
    api_key: Any = Column(String(100), nullable=True)
    role: Any = Column(String(20), default="user")  # "user" or "admin"
    created_at: Any = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    accounts: Mapped[List["Account"]] = relationship("Account", back_populates="owner", lazy="selectin")


class Account(Base):
    """
    Bank account model.

    Vulnerabilities present:
    - No server-side ownership check in vulnerable mode (BOLA/IDOR)
    """

    __tablename__ = "accounts"

    id: Any = Column(Integer, primary_key=True, autoincrement=True)
    user_id: Any = Column(Integer, ForeignKey("users.id"), nullable=False)
    account_number: Any = Column(String(50), unique=True, nullable=False)
    balance: Any = Column(Float, default=0.0)
    account_type: Any = Column(String(20), default="checking")  # checking, savings
    created_at: Any = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="accounts")
    transactions: Mapped[List["Transaction"]] = relationship(
        "Transaction",
        back_populates="account",
        foreign_keys="[Transaction.account_id]",
        lazy="selectin",
    )


class Transaction(Base):
    """Bank transaction model."""

    __tablename__ = "transactions"

    id: Any = Column(Integer, primary_key=True, autoincrement=True)
    account_id: Any = Column(Integer, ForeignKey("accounts.id"), nullable=False)
    amount: Any = Column(Float, nullable=False)
    transaction_type: Any = Column(String(20), nullable=False)  # credit, debit, transfer
    description: Any = Column(String(200), nullable=True)
    recipient_account_id: Any = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    created_at: Any = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    account: Mapped["Account"] = relationship(
        "Account", back_populates="transactions", foreign_keys=[account_id]
    )
