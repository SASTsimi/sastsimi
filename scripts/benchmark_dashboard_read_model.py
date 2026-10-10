"""Isolated load/concurrency probe for dashboard read-model pagination."""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import time
import tracemalloc
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from sastsimi.dashboard.read_model import INDEXED_TABS, DashboardReadModel
from sastsimi.simple_runtime.models import SimpleAnalysisRun
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore


def _item(tab: str, number: int) -> dict[str, object]:
    stamp = f"2026-10-10T00:{number % 60:02d}:{number % 60:02d}Z"
    if tab == "findings":
        return {
            "hypothesis_id": f"LOAD-H-{number:05d}",
            "title": f"LOAD-TEST hypothesis {number}",
            "status": "HOLD",
            "updated_at": stamp,
        }
    if tab == "coverage":
        return {
            "location": f"load/file_{number:05d}.py:{number}",
            "tools": ["semgrep"],
            "rule_ids": [f"LOAD-{number % 17}"],
        }
    if tab == "artifacts":
        return {
            "artifact_id": f"{number:064x}",
            "kind": "evidence" if number % 2 else "poc",
            "data_kind": "artifact",
            "label_ko": f"LOAD-TEST artifact {number}",
            "created_at": stamp,
        }
    if tab == "llm":
        return {
            "invocation_id": f"LOAD-LLM-{number:05d}",
            "agent_role": "LOAD Agent",
            "model": "load-model",
            "status": "SUCCEEDED",
            "started_at": stamp,
        }
    return {
        "output_type": "report",
        "artifact": None,
        "report": {
            "display_id": f"LOAD-F-{number:05d}",
            "title": f"LOAD-TEST report {number}",
            "created_at": stamp,
        },
    }


def _pages(count: int) -> dict[str, tuple[list[dict[str, object]], dict[str, object]]]:
    return {
        tab: (
            [_item(tab, number) for number in range(count)],
            {"tab": tab, "summary": {"load_test": count}},
        )
        for tab in INDEXED_TABS
    }


def _seed_logs(database: Path, count: int) -> None:
    with sqlite3.connect(database) as connection:
        AgentActivityStore.initialize_connection(connection)

        def rows() -> Iterator[tuple[object, ...]]:
            for number in range(1, count + 1):
                event = {
                    "event_id": f"load-event-{number:06d}",
                    "analysis_id": "LOAD-10000",
                    "workspace_id": "load-workspace",
                    "commit_id": "load-test",
                    "hypothesis_id": f"LOAD-H-{number % 10000:05d}",
                    "stage": "LOAD_TEST",
                    "agent_role": "LOAD Agent",
                    "attempt_id": f"load-attempt-{number:06d}",
                    "sequence": number,
                    "kind": "STAGE_COMPLETED",
                    "status": "SUCCEEDED",
                    "summary_ko": f"LOAD-TEST event {number}",
                    "input_refs": [],
                    "output_refs": [],
                    "tool_result_refs": [],
                    "started_at": "2026-10-10T00:00:00Z",
                }
                yield (
                    event["event_id"],
                    event["analysis_id"],
                    event["hypothesis_id"],
                    event["attempt_id"],
                    event["sequence"],
                    json.dumps(event, separators=(",", ":")),
                    event["started_at"],
                )

        connection.executemany(
            """INSERT INTO agent_activity_events
            (event_id,analysis_id,hypothesis_key,attempt_id,sequence,event_json,started_at)
            VALUES (?,?,?,?,?,?,?)""",
            rows(),
        )


def _measure(
    model: DashboardReadModel, analysis_id: str, tab: str, offset: int
) -> dict[str, object]:
    samples = []
    payload = None
    for _ in range(5):
        started = time.perf_counter()
        payload = model.page(analysis_id, tab, offset=offset, limit=10)
        samples.append((time.perf_counter() - started) * 1000)
    assert payload is not None
    return {
        "median_ms": round(statistics.median(samples), 3),
        "items": len(payload["items"]),
        "bytes": len(json.dumps(payload, ensure_ascii=False).encode()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--items", type=int, default=10_000)
    parser.add_argument("--logs", type=int, default=100_000)
    args = parser.parse_args()
    if args.data_dir.exists():
        raise SystemExit("load-test data directory already exists; refusing overwrite")
    model = DashboardReadModel(args.data_dir)
    model.initialize()
    store = SimpleCheckpointStore(model.database)
    for analysis_id, display_id in (
        ("LOAD-100", "LOAD-100"),
        ("LOAD-10000", "LOAD-10000"),
    ):
        store.save_analysis_run(
            SimpleAnalysisRun(
                analysis_id=analysis_id,
                display_analysis_id=display_id,
                workspace_id="LOAD-WORKSPACE",
                commit_id="LOAD-TEST",
                repository=f"https://example.invalid/{analysis_id.lower()}.git",
                provider="load-test",
                model="load-test",
                started_at=datetime(2026, 10, 10, tzinfo=UTC),
            )
        )
    model.replace("LOAD-100", "load-100", _pages(100))
    model.replace("LOAD-10000", "load-10000", _pages(args.items))
    with sqlite3.connect(model.database) as connection:
        now = "2026-10-10T00:00:00Z"
        connection.executemany(
            """INSERT OR IGNORE INTO dashboard_index_state
            (analysis_id,projection_version,source_marker,status,last_error,indexed_at)
            VALUES (?,1,'load','READY',NULL,?)""",
            ((f"LOAD-ANALYSIS-{number:03d}", now) for number in range(98)),
        )
    _seed_logs(model.database, args.logs)
    report: dict[str, object] = {
        "items_per_kind": args.items,
        "logs": args.logs,
        "analyses": 100,
    }
    tracemalloc.start()
    timings = {}
    for tab in INDEXED_TABS:
        timings[tab] = {
            "first": _measure(model, "LOAD-10000", tab, 0),
            "middle": _measure(model, "LOAD-10000", tab, args.items // 2),
            "last": _measure(model, "LOAD-10000", tab, max(0, args.items - 10)),
            "small_100": _measure(model, "LOAD-100", tab, 0),
        }
    report["timings"] = timings
    report["peak_python_bytes"] = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    with sqlite3.connect(model.database) as connection:
        report["query_plan"] = [
            row[3]
            for row in connection.execute(
                """EXPLAIN QUERY PLAN SELECT payload_json FROM dashboard_list_items
                WHERE analysis_id=? AND list_kind=?
                ORDER BY sort_ordinal DESC,item_id DESC LIMIT 10 OFFSET 5000""",
                ("LOAD-10000", "artifacts"),
            )
        ]
        started = time.perf_counter()
        all_rows = connection.execute(
            "SELECT payload_json FROM dashboard_list_items "
            "WHERE analysis_id=? AND list_kind=?",
            ("LOAD-10000", "artifacts"),
        ).fetchall()
        report["naive_full_read_ms"] = round((time.perf_counter() - started) * 1000, 3)
        report["naive_full_rows"] = len(all_rows)

    def reader() -> int:
        return sum(
            len(
                model.page("LOAD-10000", "artifacts", offset=index * 10, limit=10)[
                    "items"
                ]
            )
            for index in range(25)
        )

    def searcher() -> int:
        return int(
            model.page(
                "LOAD-10000", "artifacts", offset=0, limit=10, query="artifact 99"
            )["total_items"]
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(reader) for _ in range(4)] + [
            pool.submit(searcher) for _ in range(2)
        ]
        report["concurrency_results"] = [future.result() for future in futures]
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
