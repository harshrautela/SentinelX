"""
Response Analyzer
-----------------
Extracts structural and semantic features from HTTP responses.
Identifies error signatures, content types, and structural patterns.
"""

import json
import re
from typing import Any, Dict, List, Optional
import httpx

from app.evidence.models import ResponseRecord


# Known database error regex patterns for SQL injection detection
DB_ERROR_PATTERNS = [
    # SQLite
    re.compile(r"sqlite3?\.(OperationalError|DatabaseError)", re.IGNORECASE),
    re.compile(r"(unrecognized token|syntax error|unclosed quotation mark)", re.IGNORECASE),
    re.compile(r"near \".*\": syntax error", re.IGNORECASE),
    
    # PostgreSQL
    re.compile(r"pg_query\(\)|syntax error at or near", re.IGNORECASE),
    re.compile(r"PSQLException|PostgreSQL.*ERROR", re.IGNORECASE),
    
    # MySQL / MariaDB
    re.compile(r"SQL syntax.*MySQL|Warning.*mysql_", re.IGNORECASE),
    re.compile(r"valid MySQL result|MySqlException", re.IGNORECASE),
    
    # Generic SQL errors
    re.compile(r"SQLSTATE\[\d+\]", re.IGNORECASE),
    re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
]


class ResponseAnalyzer:
    """Analyzes captured HTTP responses for security anomalies."""

    @staticmethod
    def to_record(response: httpx.Response, elapsed_ms: float = 0.0) -> ResponseRecord:
        """Convert an httpx Response into an Evidence ResponseRecord."""
        headers = dict(response.headers)
        body = response.text
        return ResponseRecord(
            status_code=response.status_code,
            headers=headers,
            body=body,
            elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def parse_json(body: str) -> Optional[Any]:
        """Safely parse body as JSON if possible."""
        try:
            return json.loads(body)
        except Exception:
            return None

    @staticmethod
    def find_database_errors(text: str) -> List[str]:
        """Check text against database error signatures."""
        matches: List[str] = []
        for pattern in DB_ERROR_PATTERNS:
            found = pattern.findall(text)
            if found:
                for match in found:
                    if isinstance(match, tuple):
                        matches.extend([m for m in match if m])
                    else:
                        matches.append(match)
        return list(set(matches))
