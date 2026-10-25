"""
Severity Calculation Engine
---------------------------
Calculates transparent risk scores and severity ratings based on:
1. Exploitability (Ease of triggering the issue)
2. Impact (Consequence to confidentiality, integrity, availability)
3. Confidence (Strength of captured evidence)
"""

from dataclasses import dataclass
from typing import Tuple
from app.risk.cvss import Confidence, Exploitability, Impact


@dataclass
class SeverityResult:
    score: float
    severity: str
    rationale: str


class SeverityCalculator:
    """Transparent risk calculation based on VAPT methodology."""

    EXPLOITABILITY_WEIGHTS = {
        Exploitability.EASY: 3.5,
        Exploitability.MODERATE: 2.2,
        Exploitability.DIFFICULT: 1.0,
    }

    IMPACT_WEIGHTS = {
        Impact.CRITICAL: 5.5,
        Impact.HIGH: 4.5,
        Impact.MEDIUM: 3.0,
        Impact.LOW: 1.5,
        Impact.INFO: 0.5,
    }

    CONFIDENCE_MULTIPLIERS = {
        Confidence.HIGH: 1.0,
        Confidence.MEDIUM: 0.85,
        Confidence.LOW: 0.65,
    }

    @classmethod
    def calculate(
        cls,
        exploitability: Exploitability,
        impact: Impact,
        confidence: Confidence = Confidence.HIGH,
        context_notes: str = "",
    ) -> SeverityResult:
        """
        Compute transparent 0.0 - 10.0 risk score and mapped severity category.
        """
        base_score = cls.EXPLOITABILITY_WEIGHTS.get(exploitability, 2.0) + cls.IMPACT_WEIGHTS.get(impact, 2.0)
        multiplier = cls.CONFIDENCE_MULTIPLIERS.get(confidence, 1.0)
        final_score = min(10.0, round(base_score * multiplier, 1))

        if final_score >= 9.0:
            severity = "CRITICAL"
        elif final_score >= 7.0:
            severity = "HIGH"
        elif final_score >= 4.0:
            severity = "MEDIUM"
        elif final_score >= 2.0:
            severity = "LOW"
        else:
            severity = "INFO"

        rationale = (
            f"Score {final_score}/10 ({severity}): Exploitability is {exploitability.value} "
            f"(weight {cls.EXPLOITABILITY_WEIGHTS.get(exploitability)}), Impact is {impact.value} "
            f"(weight {cls.IMPACT_WEIGHTS.get(impact)}), Confidence is {confidence.value} "
            f"(factor {multiplier}). {context_notes}".strip()
        )

        return SeverityResult(score=final_score, severity=severity, rationale=rationale)
