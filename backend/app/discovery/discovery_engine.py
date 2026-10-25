"""
SentinelX Discovery Engine
--------------------------
Orchestrates API discovery:
1. Validates target and spec URLs against SSRF policies.
2. Retrieves OpenAPI JSON specification via HTTP or parses supplied spec.
3. Extracts endpoints, parameters, and authentication requirements.
4. Persists discovered endpoints to the database for security scanning.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.core.security import validate_target_url, SecurityValidationError
from app.discovery.endpoint_model import DiscoveredEndpointDTO
from app.discovery.openapi_parser import OpenAPIParser
from app.models.endpoint import DiscoveredEndpoint
from app.models.scan import Scan


class DiscoveryEngine:
    """Engine responsible for API surface discovery and parameter analysis."""

    def __init__(self, db: Session):
        self.db = db

    async def fetch_openapi_spec(self, target_url: str, openapi_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch OpenAPI spec from URL.
        If openapi_url is not specified, tries common endpoints (/openapi.json, /docs/openapi.json, /swagger.json).
        """
        candidate_urls: List[str] = []
        if openapi_url:
            candidate_urls.append(openapi_url)
        else:
            candidate_urls.extend([
                urljoin(target_url, "/openapi.json"),
                urljoin(target_url, "/swagger.json"),
                urljoin(target_url, "/api/v1/openapi.json"),
            ])

        async with httpx.AsyncClient(timeout=settings.request_timeout, verify=False) as client:
            last_err = None
            for url in candidate_urls:
                # SSRF validation on target spec URL
                is_valid, err_msg = validate_target_url(url)
                if not is_valid:
                    raise SecurityValidationError(f"OpenAPI URL security validation failed: {err_msg}")

                try:
                    logger.info(f"Attempting to fetch OpenAPI spec from: {url}")
                    response = await client.get(url)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, dict) and ("paths" in data or "openapi" in data or "swagger" in data):
                            logger.info(f"Successfully retrieved OpenAPI spec from: {url}")
                            return data
                except Exception as e:
                    last_err = e
                    continue

        raise ValueError(f"Failed to fetch valid OpenAPI specification from target: {last_err or 'No valid schema found'}")

    async def discover_and_persist(
        self,
        scan_id: str,
        target_url: str,
        openapi_url: Optional[str] = None,
        inline_spec: Optional[Dict[str, Any]] = None,
    ) -> List[DiscoveredEndpoint]:
        """
        Run discovery for a given scan and persist results to DB.
        """
        # Validate target URL
        is_valid, err_msg = validate_target_url(target_url)
        if not is_valid:
            raise SecurityValidationError(f"Target URL security validation failed: {err_msg}")

        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with id {scan_id} not found")

        scan.status = "DISCOVERING"
        self.db.commit()

        try:
            # Get spec
            if inline_spec:
                spec = inline_spec
            else:
                spec = await self.fetch_openapi_spec(target_url, openapi_url)

            # Parse spec
            parser = OpenAPIParser(spec)
            endpoint_dtos = parser.extract_endpoints()

            # Persist to database
            db_endpoints: List[DiscoveredEndpoint] = []
            for dto in endpoint_dtos:
                db_endpoint = DiscoveredEndpoint(
                    scan_id=scan.id,
                    method=dto.method,
                    path=dto.path,
                    summary=dto.summary,
                    description=dto.description,
                    parameters={"params": [p.model_dump() for p in dto.parameters]},
                    request_body_schema=dto.request_body_schema,
                    response_schema=dto.response_schema,
                    auth_required=dto.auth_required,
                    auth_schemes=dto.auth_schemes,
                    content_type=dto.content_type,
                )
                self.db.add(db_endpoint)
                db_endpoints.append(db_endpoint)

            scan.total_endpoints = len(db_endpoints)
            scan.status = "DISCOVERED"
            self.db.commit()

            logger.info(f"Discovery completed for scan {scan_id}: {len(db_endpoints)} endpoints persisted.")
            return db_endpoints

        except Exception as e:
            scan.status = "FAILED"
            scan.error_message = str(e)
            self.db.commit()
            logger.error(f"Discovery failed for scan {scan_id}: {str(e)}")
            raise
