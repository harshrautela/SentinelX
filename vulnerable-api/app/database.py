"""
VulnBank Database Engine & Seed Data
-------------------------------------
Initializes SQLite, creates tables, and seeds test data on startup.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Account, Base, Transaction, User

if settings.database_url.startswith("sqlite:///"):
    db_path_str = settings.database_url.replace("sqlite:///", "")
    if db_path_str != ":memory:":
        db_path = Path(db_path_str)
        db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def hash_password(password: str) -> str:
    """
    Intentionally weak password hashing — MD5.

    This is a DELIBERATE VULNERABILITY for testing.
    Production systems should use bcrypt/argon2.
    """
    return hashlib.md5(password.encode()).hexdigest()


def get_db():
    """FastAPI dependency: yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_data(db: Session) -> None:
    """Populate the database with test users, accounts, and transactions."""
    if db.query(User).first():
        return  # Already seeded

    # --- Users ---
    users = [
        User(
            id=1,
            username="alice",
            email="alice@vulnbank.com",
            password_hash=hash_password("password123"),
            api_key="ak_alice_secret_key_12345",
            role="user",
        ),
        User(
            id=2,
            username="bob",
            email="bob@vulnbank.com",
            password_hash=hash_password("password456"),
            api_key="ak_bob_secret_key_67890",
            role="user",
        ),
        User(
            id=3,
            username="admin",
            email="admin@vulnbank.com",
            password_hash=hash_password("admin123"),
            api_key="ak_admin_master_key_99999",
            role="admin",
        ),
    ]
    db.add_all(users)
    db.flush()

    # --- Accounts ---
    accounts = [
        Account(
            id=101,
            user_id=1,
            account_number="ACC-001-ALICE",
            balance=10000.00,
            account_type="checking",
        ),
        Account(
            id=102,
            user_id=2,
            account_number="ACC-002-BOB",
            balance=5000.00,
            account_type="savings",
        ),
        Account(
            id=103,
            user_id=3,
            account_number="ACC-003-ADMIN",
            balance=100000.00,
            account_type="checking",
        ),
    ]
    db.add_all(accounts)
    db.flush()

    # --- Transactions ---
    now = datetime.now(timezone.utc)
    transactions = [
        Transaction(
            account_id=101,
            amount=5000.00,
            transaction_type="credit",
            description="Salary deposit",
            created_at=now - timedelta(days=10),
        ),
        Transaction(
            account_id=101,
            amount=5000.00,
            transaction_type="credit",
            description="Bonus payment",
            created_at=now - timedelta(days=8),
        ),
        Transaction(
            account_id=101,
            amount=-50.00,
            transaction_type="debit",
            description="Coffee shop",
            created_at=now - timedelta(days=5),
        ),
        Transaction(
            account_id=101,
            amount=-120.00,
            transaction_type="debit",
            description="Electric bill",
            created_at=now - timedelta(days=3),
        ),
        Transaction(
            account_id=102,
            amount=3000.00,
            transaction_type="credit",
            description="Freelance payment",
            created_at=now - timedelta(days=7),
        ),
        Transaction(
            account_id=102,
            amount=2000.00,
            transaction_type="credit",
            description="Refund",
            created_at=now - timedelta(days=4),
        ),
        Transaction(
            account_id=102,
            amount=-200.00,
            transaction_type="debit",
            description="Grocery store",
            created_at=now - timedelta(days=2),
        ),
        Transaction(
            account_id=101,
            amount=-100.00,
            transaction_type="transfer",
            description="Transfer to Bob",
            recipient_account_id=102,
            created_at=now - timedelta(days=1),
        ),
    ]
    db.add_all(transactions)
    db.commit()


def init_db() -> None:
    """Create all tables and seed initial data."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_data(db)
    finally:
        db.close()
