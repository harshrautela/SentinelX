"""
VulnBank Search Routes
-----------------------
GET /api/v1/search?q=<query> — Search users

⚠️  VULNERABILITY: SQL INJECTION
Uses raw string concatenation in the SQL query.
Also exposes database error messages in the response.
In secure mode, uses parameterized queries.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db

router = APIRouter(prefix="/api/v1", tags=["Search"])


@router.get("/search")
def search_users(
    q: str = Query(..., description="Search query for usernames or emails"),
    db: Session = Depends(get_db),
):
    """
    Search for users by username or email.

    VULNERABLE MODE: Raw SQL string concatenation — SQL injection possible.
    Test payloads:
    - ' OR '1'='1
    - ' UNION SELECT 1,2,3,4,5,6,7--
    - '

    SECURE MODE: Parameterized query.
    """
    if settings.secure_mode:
        # SECURE: parameterized query, limited columns
        result = db.execute(
            text("SELECT id, username, email FROM users WHERE username LIKE :q OR email LIKE :q"),
            {"q": f"%{q}%"},
        )
        rows = result.fetchall()
        return {
            "query": q,
            "results": [
                {"id": row[0], "username": row[1], "email": row[2]}
                for row in rows
            ],
            "count": len(rows),
        }
    else:
        # ⚠️  VULNERABLE: raw SQL string concatenation
        raw_query = f"SELECT id, username, email, role, api_key FROM users WHERE username LIKE '%{q}%'"
        try:
            result = db.execute(text(raw_query))
            rows = result.fetchall()
            return {
                "query": q,
                "results": [
                    {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "role": row[3],
                        "api_key": row[4],
                    }
                    for row in rows
                ],
                "count": len(rows),
            }
        except Exception as e:
            # ⚠️  VULNERABLE: exposes database error messages
            return {
                "query": q,
                "error": str(e),
                "results": [],
                "count": 0,
            }
