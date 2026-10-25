"""
Unit tests for Response Comparator
"""

import json
from app.evidence.models import ResponseRecord
from app.scanner.comparison import ResponseComparator


def test_comparison_detects_status_change():
    """Verify that comparator catches status code changes."""
    base = ResponseRecord(status_code=200, body='{"status": "ok"}')
    test = ResponseRecord(status_code=403, body='{"detail": "Forbidden"}')

    res = ResponseComparator.compare(base, test)
    assert res.status_match is False
    assert res.status_changed_from == 200
    assert res.status_changed_to == 403


def test_comparison_detects_ownership_change():
    """Verify that comparator detects when response returns a different user's resource."""
    base = ResponseRecord(status_code=200, body=json.dumps({"id": 101, "owner": "alice", "balance": 1000}))
    test = ResponseRecord(status_code=200, body=json.dumps({"id": 102, "owner": "bob", "balance": 5000}))

    res = ResponseComparator.compare(base, test)
    assert res.status_match is True
    assert res.semantic_ownership_different is True
    assert "different user/resource identity" in res.observation


def test_comparison_detects_structural_difference():
    """Verify that new keys in JSON responses are detected."""
    base = ResponseRecord(status_code=200, body=json.dumps({"id": 1, "username": "alice"}))
    test = ResponseRecord(status_code=200, body=json.dumps({"id": 1, "username": "alice", "api_key": "secret"}))

    res = ResponseComparator.compare(base, test)
    assert res.structure_match is False
    assert "api_key" in res.new_keys_detected
