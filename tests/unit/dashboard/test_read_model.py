from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

import sastsimi.dashboard.projection as projection_module
import sastsimi.dashboard.query as dashboard_query_module
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.dashboard.read_model import (
    INDEXED_TABS,
    DashboardIndexNotReady,
    DashboardReadModel,
    RebuildResult,
)
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.storage.agent_activity import AgentActivityStore


def _pages(count: int) -> dict[str, tuple[list[dict[str, object]], dict[str, object]]]:
    result: dict[str, tuple[list[dict[str, object]], dict[str, object]]] = {}
    for tab in INDEXED_TABS:
        items: list[dict[str, object]] = []
        for index in range(count):
            common: dict[str, object] = {
                "status": "SUCCEEDED",
                "created_at": f"2026-01-01T00:{index:02d}:00Z",
            }
            item: dict[str, object]
            if tab == "findings":
                item = common | {
                    "hypothesis_id": f"DEMO-H-{index:03d}",
                    "title": f"DEMO 가설 {index}",
                }
            elif tab == "coverage":
                item = common | {
                    "location": f"demo/file-{index}.py:{index}",
                    "tools": ["semgrep"],
                    "rule_ids": [f"DEMO-R-{index:03d}"],
                }
            elif tab == "artifacts":
                item = common | {
                    "artifact_id": f"{index:064x}",
                    "kind": "evidence" if index % 2 else "poc",
                    "data_kind": "artifact",
                    "label_ko": f"DEMO artifact {index}",
                }
            elif tab == "llm":
                item = common | {
                    "invocation_id": f"DEMO-LLM-{index:03d}",
                    "agent_role": "demo",
                    "model": "demo-model",
                }
            else:
                item = common | {
                    "output_type": "report",
                    "artifact": None,
                    "report": {
                        "display_id": f"DEMO-F-{index:03d}",
                        "created_at": common["created_at"],
                        "status": "DEMO",
                    },
                }
            items.append(item)
        result[tab] = (items, {"tab": tab, "summary": {"demo": count}})
    return result


def _items(page: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], page["items"])


def _cursor(page: dict[str, object], key: str) -> str | None:
    return cast(str | None, page[key])


@pytest.mark.parametrize("count", [0, 1, 10, 11, 23, 101])
def test_read_model_pages_are_bounded_and_stable(tmp_path: Path, count: int) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    model.replace("DEMO-ANALYSIS", "marker", _pages(count))

    collected: list[str] = []
    pages = max(1, (count + 9) // 10)
    for page_number in range(1, pages + 1):
        page = model.page(
            "DEMO-ANALYSIS", "findings", offset=(page_number - 1) * 10, limit=10
        )
        assert len(_items(page)) <= 10
        assert page["total_items"] == count
        collected.extend(str(item["hypothesis_id"]) for item in _items(page))
    assert len(collected) == len(set(collected)) == count


def test_read_model_search_and_filter_happen_before_limit(tmp_path: Path) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    model.replace("DEMO-ANALYSIS", "marker", _pages(23))

    search = model.page(
        "DEMO-ANALYSIS", "artifacts", offset=0, limit=10, query="artifact 1"
    )
    filtered = model.page(
        "DEMO-ANALYSIS", "artifacts", offset=0, limit=10, artifact_type="evidence"
    )
    assert search["total_items"] == 11
    assert filtered["total_items"] == 11
    assert len(_items(search)) == 10


def test_index_not_ready_is_not_reported_as_empty(tmp_path: Path) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    with pytest.raises(DashboardIndexNotReady):
        model.page("NOT-BACKFILLED", "findings", offset=0, limit=10)


def test_incomplete_index_fails_closed_and_can_be_rebuilt(tmp_path: Path) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    model.replace("DEMO-ANALYSIS", "marker-1", _pages(23))

    model.mark_incomplete("DEMO-ANALYSIS", "marker-failed", "injected rebuild failure")
    with pytest.raises(DashboardIndexNotReady):
        model.page("DEMO-ANALYSIS", "artifacts", offset=0, limit=10)

    model.replace("DEMO-ANALYSIS", "marker-2", _pages(23))
    recovered = model.page("DEMO-ANALYSIS", "artifacts", offset=20, limit=10)

    assert recovered["page"] == 3
    assert recovered["total_items"] == 23
    assert len(_items(recovered)) == 3


def test_dashboard_indexed_list_does_not_read_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    model.replace("DEMO-ANALYSIS", "marker", _pages(23))
    query = DashboardQuery(tmp_path)
    monkeypatch.setattr(query, "_resolved", lambda value: value)

    def fail_source(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("source projection or CAS was read")

    monkeypatch.setattr(query, "_get_analysis_tab_from_source", fail_source)
    page = query.get_analysis_tab("DEMO-ANALYSIS", "artifacts", offset=10, limit=10)
    assert len(_items(page)) == 10
    assert page["page"] == 2


def test_concurrent_reads_and_rebuilds_remain_consistent(tmp_path: Path) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    pages = _pages(125)
    model.replace("DEMO-ANALYSIS", "initial", pages)

    def read_pages() -> int:
        seen: set[str] = set()
        for offset in range(0, 125, 10):
            page = model.page("DEMO-ANALYSIS", "findings", offset=offset, limit=10)
            assert page["total_items"] == 125
            seen.update(str(item["hypothesis_id"]) for item in _items(page))
        return len(seen)

    def rebuild(number: int) -> int:
        return model.replace("DEMO-ANALYSIS", f"rebuild-{number}", pages)["findings"]

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(read_pages) for _ in range(4)]
        futures.extend(pool.submit(rebuild, number) for number in range(4))
        results = [future.result() for future in futures]

    assert results == [125] * 8
    final_page = model.page("DEMO-ANALYSIS", "findings", offset=120, limit=10)
    assert final_page["total_items"] == 125
    assert len(_items(final_page)) == 5


def _event(number: int) -> AgentActivityEvent:
    return AgentActivityEvent(
        event_id=f"event-{number:03d}",
        analysis_id="DEMO-ANALYSIS",
        workspace_id="demo-workspace",
        commit_id="demo-commit",
        hypothesis_id=f"DEMO-H-{number:03d}",
        stage="DEMO_STAGE",
        agent_role="DEMO Agent",
        attempt_id=f"attempt-{number:03d}",
        sequence=number,
        kind=ActivityKind.STAGE_COMPLETED,
        status="SUCCEEDED",
        summary_ko=f"DEMO 로그 {number}",
        started_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=number),
    )


def test_log_cursor_is_stable_when_new_event_is_appended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AgentActivityStore(tmp_path / "db" / "sastsimi.sqlite3")
    for number in range(1, 26):
        store.append(_event(number))
    query = DashboardQuery(tmp_path)
    monkeypatch.setattr(query, "_resolved", lambda value: value)

    latest = query.list_log_cursor("DEMO-ANALYSIS", limit=10)
    older = query.list_log_cursor(
        "DEMO-ANALYSIS", before=_cursor(latest, "next_cursor"), limit=10
    )
    store.append(_event(26))
    older_again = query.list_log_cursor(
        "DEMO-ANALYSIS", before=_cursor(latest, "next_cursor"), limit=10
    )
    newer = query.list_log_cursor(
        "DEMO-ANALYSIS", after=_cursor(latest, "latest_cursor"), limit=10
    )

    assert [item["event_id"] for item in _items(latest)] == [
        f"event-{number:03d}" for number in range(25, 15, -1)
    ]
    assert [item["event_id"] for item in _items(older)] == [
        f"event-{number:03d}" for number in range(15, 5, -1)
    ]
    assert older_again["items"] == older["items"]
    assert [item["event_id"] for item in _items(newer)] == ["event-026"]
    assert not set(item["event_id"] for item in _items(latest)).intersection(
        item["event_id"] for item in _items(older)
    )


def test_rebuild_failure_records_incomplete_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()

    def fail_collection(*_args: object, **_kwargs: object) -> object:
        raise ValueError("CORRUPT_SOURCE_RECORD")

    monkeypatch.setattr(projection_module, "collect_source_pages", fail_collection)
    result = projection_module.rebuild_analysis(tmp_path, "BROKEN-ANALYSIS")

    assert result.status == "FAILED"
    assert result.error == "ValueError: CORRUPT_SOURCE_RECORD"
    with pytest.raises(DashboardIndexNotReady):
        model.page("BROKEN-ANALYSIS", "findings", offset=0, limit=10)


def test_rebuild_all_continues_after_one_analysis_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Summary:
        def __init__(self, analysis_id: str) -> None:
            self.analysis_id = analysis_id

    class Query:
        def __init__(self, _data_dir: Path) -> None:
            pass

        def list_analyses(self) -> tuple[Summary, ...]:
            return (Summary("GOOD-1"), Summary("BROKEN"), Summary("GOOD-2"))

    def rebuild(
        _data_dir: Path, analysis_id: str, *, dry_run: bool = False
    ) -> RebuildResult:
        status = "FAILED" if analysis_id == "BROKEN" else "READY"
        return RebuildResult(
            analysis_id,
            {},
            {},
            dry_run,
            status,
            "CORRUPT_SOURCE_RECORD" if status == "FAILED" else None,
        )

    monkeypatch.setattr(dashboard_query_module, "DashboardQuery", Query)
    monkeypatch.setattr(projection_module, "rebuild_analysis", rebuild)
    results = projection_module.rebuild_all(tmp_path)

    assert [item.analysis_id for item in results] == ["GOOD-1", "BROKEN", "GOOD-2"]
    assert [item.status for item in results] == ["READY", "FAILED", "READY"]
