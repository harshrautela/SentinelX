"""
Request Builder
---------------
Constructs HTTP requests from DiscoveredEndpoint metadata and test payloads.
Handles path interpolation, query building, body formatting, and auth token injection.
"""

from typing import Any, Dict, Optional
from urllib.parse import urljoin


class RequestBuilder:
    """Builds HTTP request specifications for scanner tests."""

    @staticmethod
    def build_url(base_url: str, path_template: str, path_params: Optional[Dict[str, Any]] = None) -> str:
        """
        Interpolate path parameters into endpoint path template.
        e.g. path_template = "/api/v1/accounts/{id}", path_params = {"id": 102}
        """
        resolved_path = path_template
        if path_params:
            for param_name, param_value in path_params.items():
                resolved_path = resolved_path.replace(f"{{{param_name}}}", str(param_value))
                resolved_path = resolved_path.replace(f"{{{param_name}:int}}", str(param_value))
                resolved_path = resolved_path.replace(f"{{{param_name}:str}}", str(param_value))

        return urljoin(base_url.rstrip("/") + "/", resolved_path.lstrip("/"))

    @staticmethod
    def build_headers(
        token: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        content_type: str = "application/json",
    ) -> Dict[str, str]:
        """Build headers dictionary including Authorization bearer token if provided."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "SentinelX-VAPT-Scanner/1.0 (Authorized Security Testing)",
        }
        if content_type:
            headers["Content-Type"] = content_type
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if custom_headers:
            headers.update(custom_headers)
        return headers
