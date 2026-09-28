from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.facts import extract_flows
from sastsimi.simple_runtime.feeding import plan_survey_feed


def test_python_route_facts_are_deterministic(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@router.get('/items')\ndef items(user):\n    return db.lookup(user)\n",
        encoding="utf-8",
    )

    first = extract_flows(tmp_path, ("app.py",))
    second = extract_flows(tmp_path, ("app.py",))

    assert first == second
    assert first["entry_points"][0]["file"] == "app.py"
    assert first["entry_points"][0]["line"] == 2
    assert "db.lookup" in first["entry_points"][0]["calls"]
    assert plan_survey_feed(tmp_path, ("app.py",)).kind == "facts"


def test_non_python_or_empty_routes_fall_back_to_source(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "server.get('/items', handler);\n", encoding="utf-8"
    )

    feed = plan_survey_feed(tmp_path, ("app.js",))

    assert feed.kind == "code"
    assert "server.get" in feed.content


def test_untracked_and_outside_symlink_are_not_fed(tmp_path: Path) -> None:
    (tmp_path / "tracked.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("PASSWORD = 'hidden'\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-route.py"
    outside.write_text("@app.get('/')\ndef secret(): pass\n", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pass

    feed = plan_survey_feed(tmp_path, ("tracked.py", "link.py"))

    assert "hidden" not in feed.content
    assert "def secret" not in feed.content
    assert "link.py" in feed.excluded


def test_fact_feed_marks_incomplete_coverage_when_prompt_budget_is_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sastsimi.simple_runtime.feeding as module

    monkeypatch.setattr(
        module,
        "extract_flows",
        lambda *_: {
            "entry_points": [
                {
                    "file": "app.py",
                    "line": index,
                    "function": f"route_{index}",
                    "routes": ["app.get"],
                    "calls": ["x" * 200],
                }
                for index in range(3_000)
            ],
            "excluded": [],
            "truncated": False,
        },
    )

    feed = plan_survey_feed(tmp_path, ("app.py",))

    assert feed.kind == "facts"
    assert len(feed.content.encode("utf-8")) <= 256_000
    assert "FACTS_BUDGET_EXHAUSTED" in feed.excluded
