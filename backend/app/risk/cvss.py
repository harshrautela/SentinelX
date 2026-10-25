"""
CVSS Scoring Constants and Enums
--------------------------------
Provides CVSS v3.1 inspired metrics and calculation helpers.
"""

from enum import Enum


class Exploitability(str, Enum):
    EASY = "EASY"          # Direct parameter tampering or unauthenticated access
    MODERATE = "MODERATE"  # Requires specific payload formulation or timing
    DIFFICULT = "DIFFICULT"# Complex prerequisites or blind deduction


class Impact(str, Enum):
    CRITICAL = "CRITICAL"  # Full unauthorized data/resource compromise or RCE
    HIGH = "HIGH"          # Access to other users' financial/private records
    MEDIUM = "MEDIUM"      # Information leakage or weak security posture
    LOW = "LOW"            # Missing hardening headers without immediate exploitability
    INFO = "INFO"          # Informational finding


class Confidence(str, Enum):
    HIGH = "HIGH"          # Confirmed via differential response or syntax error
    MEDIUM = "MEDIUM"      # Strong behavioural indicator
    LOW = "LOW"            # Potential issue based on heuristics
