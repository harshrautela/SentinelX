"""
VulnBank Configuration
----------------------
Controls whether the application runs in vulnerable or secure mode.
VULNBANK_SECURE_MODE=true patches all intentional vulnerabilities.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """VulnBank application settings."""

    # When True, all intentional vulnerabilities are patched.
    # Used for demonstrating the SentinelX retest workflow.
    secure_mode: bool = False

    # Database
    database_url: str = "sqlite:///./data/vulnbank.db"

    # JWT — intentionally weak defaults
    jwt_secret: str = "vulnbank-secret-key-do-not-use-in-prod"
    jwt_algorithm: str = "HS256"

    model_config = SettingsConfigDict(env_prefix="VULNBANK_")


settings = Settings()
