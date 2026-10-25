"""
SentinelX Configuration
-----------------------
Settings for the SentinelX VAPT engine and API backend.
Loaded from environment variables with sensible defaults.
"""

from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    # Database
    database_url: str = "sqlite:///./data/sentinelx.db"

    # Scanner Target Security / SSRF Protection
    # Only targets in this list or matching private/local IP ranges can be scanned
    allowed_targets: str = "vulnerable-api,localhost,127.0.0.1,host.docker.internal"

    # Scanner Limits (Defense in Depth / DoS Protection)
    max_requests_per_scan: int = 1000
    max_rate_limit_probe_requests: int = 20
    request_timeout: float = 10.0
    scan_concurrency: int = 5

    # Evidence Configuration
    max_evidence_body_bytes: int = 2048

    # CORS
    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    # Logging
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def allowed_target_hosts(self) -> List[str]:
        """Return list of permitted target hostnames/IPs."""
        return [h.strip() for h in self.allowed_targets.split(",") if h.strip()]

    @property
    def cors_origin_list(self) -> List[str]:
        """Return list of allowed CORS origins."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
