"""
Response Comparison Engine
--------------------------
Compares baseline vs test HTTP responses to detect authorization failures,
information leakage, and behavioral deviations.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.evidence.models import ResponseRecord


@dataclass
class ComparisonResult:
    """Detailed differential analysis between baseline and test responses."""
    status_match: bool
    status_changed_from: int
    status_changed_to: int
    length_delta: int
    length_delta_pct: float
    structure_match: bool
    new_keys_detected: List[str] = field(default_factory=list)
    missing_keys_detected: List[str] = field(default_factory=list)
    semantic_ownership_different: bool = False
    observation: str = ""


class ResponseComparator:
    """Compares baseline and test responses to detect security differences."""

    @staticmethod
    def extract_json_keys(data: Any, prefix: str = "") -> Set[str]:
        """Recursively extract all key paths from a nested dictionary or list."""
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys.update(ResponseComparator.extract_json_keys(v, full_key))
        elif isinstance(data, list) and data:
            for item in data[:3]:  # sample first few items
                keys.update(ResponseComparator.extract_json_keys(item, prefix))
        return keys

    @classmethod
    def compare(
        cls,
        baseline: ResponseRecord,
        test: ResponseRecord,
        baseline_owner_value: Optional[Any] = None,
    ) -> ComparisonResult:
        """
        Perform multidimensional comparison between baseline and test response.
        """
        status_match = baseline.status_code == test.status_code
        len_base = len(baseline.body)
        len_test = len(test.body)
        length_delta = len_test - len_base
        length_delta_pct = (abs(length_delta) / max(len_base, 1)) * 100.0

        # Try parsing JSON
        base_json = None
        test_json = None
        try:
            base_json = json.loads(baseline.body)
        except Exception:
            pass

        try:
            test_json = json.loads(test.body)
        except Exception:
            pass

        structure_match = True
        new_keys: List[str] = []
        missing_keys: List[str] = []
        semantic_ownership_different = False

        if base_json is not None and test_json is not None:
            base_keys = cls.extract_json_keys(base_json)
            test_keys = cls.extract_json_keys(test_json)

            new_keys = list(test_keys - base_keys)
            missing_keys = list(base_keys - test_keys)
            structure_match = len(new_keys) == 0 and len(missing_keys) == 0

            # Check ownership indicators (e.g., id, user_id, owner, account_number)
            ownership_fields = ["user_id", "owner", "account_number", "id", "email", "username"]
            if isinstance(base_json, dict) and isinstance(test_json, dict):
                for fld in ownership_fields:
                    if fld in base_json and fld in test_json:
                        if base_json[fld] != test_json[fld]:
                            semantic_ownership_different = True
                            break

        # Generate observation summary
        observations = []
        if not status_match:
            observations.append(f"HTTP status changed from {baseline.status_code} to {test.status_code}.")
        else:
            observations.append(f"HTTP status remained {baseline.status_code}.")

        if abs(length_delta) > 0:
            observations.append(f"Response length changed by {length_delta} bytes ({length_delta_pct:.1f}%).")

        if semantic_ownership_different:
            observations.append("Response indicates access to a different user/resource identity.")

        if new_keys:
            observations.append(f"New response fields detected: {', '.join(new_keys[:5])}.")

        return ComparisonResult(
            status_match=status_match,
            status_changed_from=baseline.status_code,
            status_changed_to=test.status_code,
            length_delta=length_delta,
            length_delta_pct=length_delta_pct,
            structure_match=structure_match,
            new_keys_detected=new_keys,
            missing_keys_detected=missing_keys,
            semantic_ownership_different=semantic_ownership_different,
            observation=" ".join(observations),
        )
