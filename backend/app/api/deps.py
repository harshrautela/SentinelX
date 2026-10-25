"""
API Dependencies
----------------
FastAPI dependency providers for database sessions and configuration.
"""

from typing import Generator
from sqlalchemy.orm import Session
from app.core.database import get_db

# Re-export for route handlers
__all__ = ["get_db"]
