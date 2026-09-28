from __future__ import annotations

from sastsimi.simple_runtime.proposals import proposal_key, validate_proposal


def test_proposal_requires_real_tracked_location() -> None:
    raw = {
        "title": "SQL injection",
        "vulnerability_type": "SQLI",
        "summary": "user input reaches query",
        "code_locations": ["app.py:2"],
        "source": "user",
        "sink": "db.execute",
        "rationale": "no sanitizer",
    }
    valid, errors = validate_proposal(raw, lines={"app.py": 3})
    assert valid == raw
    assert errors == ()
    assert proposal_key(raw) == proposal_key(dict(raw))
    assert validate_proposal(raw, lines={"app.py": 1})[0] is None
    assert validate_proposal(raw, lines={"other.py": 3})[0] is None
