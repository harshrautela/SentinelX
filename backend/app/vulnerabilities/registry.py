"""
Vulnerability Check Registry
----------------------------
Maintains the registry of active vulnerability test modules.
New checks can be added here without modifying the scanner engine.
"""

from typing import Dict, List, Optional, Type

from app.vulnerabilities.authentication import AuthBypassTest
from app.vulnerabilities.base import BaseVulnerabilityTest
from app.vulnerabilities.bola import BOLATest
from app.vulnerabilities.injection import InjectionTest
from app.vulnerabilities.jwt_analysis import JWTAnalysisTest
from app.vulnerabilities.rate_limit import RateLimitTest
from app.vulnerabilities.security_headers import SecurityHeadersTest
from app.vulnerabilities.sensitive_data import SensitiveDataTest


class VulnerabilityRegistry:
    """Registry managing all active vulnerability test modules."""

    _TESTS: List[Type[BaseVulnerabilityTest]] = [
        BOLATest,
        AuthBypassTest,
        SecurityHeadersTest,
        JWTAnalysisTest,
        SensitiveDataTest,
        InjectionTest,
        RateLimitTest,
    ]

    @classmethod
    def get_all_tests(cls) -> List[BaseVulnerabilityTest]:
        """Instantiate and return all registered vulnerability tests."""
        return [test_cls() for test_cls in cls._TESTS]

    @classmethod
    def get_test_by_type(cls, test_type: str) -> Optional[BaseVulnerabilityTest]:
        """Find and instantiate a specific test class by finding type."""
        for test_cls in cls._TESTS:
            instance = test_cls()
            if instance.name.lower() == test_type.lower() or test_type.lower() in instance.name.lower():
                return instance
            # Match common short aliases
            alias_map = {
                "bola": BOLATest,
                "auth_bypass": AuthBypassTest,
                "headers": SecurityHeadersTest,
                "jwt": JWTAnalysisTest,
                "sensitive_data": SensitiveDataTest,
                "injection": InjectionTest,
                "rate_limit": RateLimitTest,
            }
            if test_type.lower() in alias_map:
                return alias_map[test_type.lower()]()
        return None
