from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore


def test_analysis_display_ids_are_stable_and_resolvable(tmp_path: Path) -> None:
    store = AnalysisDisplayIdStore(tmp_path / "sastsimi.sqlite3")

    assert store.get_or_allocate("analysis-exact-a") == "A-001"
    assert store.get_or_allocate("analysis-exact-a") == "A-001"
    assert store.get_or_allocate("analysis-exact-b") == "A-002"
    assert store.resolve("A-001") == "analysis-exact-a"
    assert store.resolve("analysis-exact-a") == "analysis-exact-a"


def test_analysis_display_id_concurrent_allocation_is_unique(tmp_path: Path) -> None:
    database = tmp_path / "sastsimi.sqlite3"

    def allocate(analysis_id: str) -> str:
        return AnalysisDisplayIdStore(database).get_or_allocate(analysis_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = tuple(pool.map(allocate, ("analysis-a", "analysis-b")))

    assert set(values) == {"A-001", "A-002"}


@pytest.mark.parametrize("value", ["A-1", "../A-001", "A-001.md", "a-001"])
def test_analysis_display_id_rejects_invalid_alias(tmp_path: Path, value: str) -> None:
    store = AnalysisDisplayIdStore(tmp_path / "sastsimi.sqlite3")

    with pytest.raises((ValueError, LookupError)):
        store.resolve(value)
