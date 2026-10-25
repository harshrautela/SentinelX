"""
Evidence Collector Engine
-------------------------
Collects, sanitizes, and persists reproducible technical evidence.
Enforces:
- Sensitive token / secret masking before persistence
- Body truncation to prevent unbounded DB growth
- Standardized observation and comparison summaries
"""

from typing import Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import mask_sensitive_data
from app.evidence.models import EvidenceArtifact
from app.models.evidence import Evidence


class EvidenceCollector:
    """Manages the sanitization and storage of evidence artifacts."""

    def __init__(self, db: Session):
        self.db = db

    def sanitize_headers(self, headers: dict) -> dict:
        """Mask sensitive headers like Authorization or Cookie."""
        sanitized = {}
        for k, v in headers.items():
            if k.lower() in ("authorization", "cookie", "x-api-key"):
                sanitized[k] = mask_sensitive_data(str(v))
            else:
                sanitized[k] = str(v)
        return sanitized

    def truncate_and_mask_body(self, body: Optional[str]) -> str:
        """Truncate body to max size and mask sensitive fields."""
        if not body:
            return ""
        masked = mask_sensitive_data(body)
        limit = settings.max_evidence_body_bytes
        if len(masked) > limit:
            return masked[:limit] + f"\n... [TRUNCATED - {len(masked) - limit} bytes omitted]"
        return masked

    def persist_evidence(
        self,
        vulnerability_id: str,
        artifact: EvidenceArtifact,
    ) -> Evidence:
        """Create and commit an Evidence record in the database."""
        orig_req_dict = None
        orig_status = None
        orig_body = None

        if artifact.original_request:
            orig_req_dict = {
                "method": artifact.original_request.method,
                "url": artifact.original_request.url,
                "headers": self.sanitize_headers(artifact.original_request.headers),
                "body": self.truncate_and_mask_body(str(artifact.original_request.body) if artifact.original_request.body else ""),
            }

        if artifact.original_response:
            orig_status = artifact.original_response.status_code
            orig_body = self.truncate_and_mask_body(artifact.original_response.body)

        test_req_dict = {}
        test_status = 0
        test_body = ""

        if artifact.test_request:
            test_req_dict = {
                "method": artifact.test_request.method,
                "url": artifact.test_request.url,
                "headers": self.sanitize_headers(artifact.test_request.headers),
                "body": self.truncate_and_mask_body(str(artifact.test_request.body) if artifact.test_request.body else ""),
            }

        if artifact.test_response:
            test_status = artifact.test_response.status_code
            test_body = self.truncate_and_mask_body(artifact.test_response.body)

        evidence = Evidence(
            vulnerability_id=vulnerability_id,
            evidence_type=artifact.evidence_type,
            original_request=orig_req_dict,
            original_status=orig_status,
            original_response_excerpt=orig_body,
            test_request=test_req_dict,
            test_status=test_status,
            test_response_excerpt=test_body,
            observation=artifact.observation,
            confidence=artifact.confidence,
        )

        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)
        return evidence
