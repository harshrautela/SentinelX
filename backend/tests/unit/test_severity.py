"""
Unit tests for Severity and Risk calculation
"""

from app.risk.cvss import Confidence, Exploitability, Impact
from app.risk.severity import SeverityCalculator


def test_severity_calculator_critical_injection():
    """Verify that easy exploitability with critical impact yields high/critical score."""
    res = SeverityCalculator.calculate(
        exploitability=Exploitability.EASY,
        impact=Impact.CRITICAL,
        confidence=Confidence.HIGH,
    )
    assert res.score >= 9.0
    assert res.severity == "CRITICAL"
    assert "Score" in res.rationale


def test_severity_calculator_bola_high():
    """Verify that BOLA with High impact yields High severity."""
    res = SeverityCalculator.calculate(
        exploitability=Exploitability.EASY,
        impact=Impact.HIGH,
        confidence=Confidence.HIGH,
    )
    assert 7.0 <= res.score <= 8.9
    assert res.severity == "HIGH"


def test_severity_calculator_headers_medium_low():
    """Verify that missing headers with low/medium impact yield appropriate tier."""
    res_med = SeverityCalculator.calculate(
        exploitability=Exploitability.DIFFICULT,
        impact=Impact.MEDIUM,
        confidence=Confidence.HIGH,
    )
    assert res_med.severity == "MEDIUM"

    res_low = SeverityCalculator.calculate(
        exploitability=Exploitability.DIFFICULT,
        impact=Impact.LOW,
        confidence=Confidence.HIGH,
    )
    assert res_low.severity == "LOW"
