"""Create an isolated DEMO dashboard fixture. Never writes the configured user DB."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sastsimi.dashboard.query import DashboardQuery
from sastsimi.dashboard.read_model import DashboardReadModel, collect_source_pages
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.storage.agent_activity import AgentActivityStore


def _clone_item(
    tab: str, template: dict[str, object], number: int
) -> dict[str, object]:
    item = copy.deepcopy(template)
    suffix = f"{number:03d}"
    item["created_at"] = (
        datetime(2026, 10, 10, tzinfo=UTC) + timedelta(seconds=number)
    ).isoformat()
    if tab == "findings":
        item["hypothesis_id"] = f"DEMO-H-{suffix}"
        item["title"] = f"DEMO 전용 취약점 가설 {suffix}"
        item["summary"] = "DEMO 화면 검증용 데이터이며 실제 Finding이 아닙니다."
    elif tab == "coverage":
        item["location"] = f"demo/fixture_{suffix}.py:{number + 1}"
        item["rule_ids"] = [f"DEMO-RULE-{suffix}"]
    elif tab == "artifacts":
        item["artifact_id"] = hashlib.sha256(
            f"DEMO-ARTIFACT-{suffix}".encode()
        ).hexdigest()
        item["label_ko"] = f"DEMO 전용 아티팩트 {suffix}"
        item["purpose_ko"] = "페이지네이션 검증용이며 실제 증거가 아닙니다."
    elif tab == "llm":
        item["invocation_id"] = f"DEMO-LLM-{suffix}"
        item["agent_role"] = "DEMO Agent"
        item["model"] = "demo-model"
    elif tab == "outputs":
        artifact = item.get("artifact")
        report = item.get("report")
        if isinstance(artifact, dict):
            artifact["artifact_id"] = hashlib.sha256(
                f"DEMO-OUTPUT-{suffix}".encode()
            ).hexdigest()
            artifact["label_ko"] = f"DEMO 전용 결과물 {suffix}"
        elif isinstance(report, dict):
            report["display_id"] = f"DEMO-F-{suffix}"
            report["title"] = f"DEMO 전용 보고서 {suffix}"
    return item


def _expand_pages(
    pages: dict[str, tuple[list[dict[str, object]], dict[str, object]]],
    count: int,
) -> dict[str, tuple[list[dict[str, object]], dict[str, object]]]:
    expanded = {}
    for tab, (source, summary) in pages.items():
        if not source:
            raise ValueError(f"DEMO_SOURCE_EMPTY:{tab}")
        items = [copy.deepcopy(item) for item in source[:count]]
        while len(items) < count:
            items.append(
                _clone_item(tab, source[(len(items) - 1) % len(source)], len(items) + 1)
            )
        expanded[tab] = (items[:count], summary)
    return expanded


def _duplicate_histories(database: Path, analysis_id: str, count: int) -> None:
    with sqlite3.connect(database) as connection:
        run = connection.execute(
            "SELECT run_json FROM simple_analysis_runs WHERE analysis_id=?",
            (analysis_id,),
        ).fetchone()
        checkpoints = connection.execute(
            """SELECT hypothesis_key,stage,checkpoint_json,input_hash,updated_at
            FROM simple_runtime_checkpoints WHERE analysis_id=?""",
            (analysis_id,),
        ).fetchall()
        if run is None:
            raise ValueError("DEMO_SOURCE_RUN_MISSING")
        for number in range(1, count):
            new_id = f"DEMO-HISTORY-{number:03d}"
            run_json = str(run[0]).replace(analysis_id, new_id)
            connection.execute(
                "INSERT OR REPLACE INTO simple_analysis_runs VALUES (?,?)",
                (new_id, run_json),
            )
            for (
                hypothesis_key,
                stage,
                checkpoint_json,
                input_hash,
                updated_at,
            ) in checkpoints:
                connection.execute(
                    """INSERT OR REPLACE INTO simple_runtime_checkpoints
                    (analysis_id,hypothesis_key,stage,checkpoint_json,input_hash,updated_at)
                    VALUES (?,?,?,?,?,?)""",
                    (
                        new_id,
                        hypothesis_key,
                        stage,
                        str(checkpoint_json).replace(analysis_id, new_id),
                        input_hash,
                        updated_at,
                    ),
                )


def _seed_logs(database: Path, analysis_id: str, count: int) -> None:
    store = AgentActivityStore(database)
    for number in range(1, count + 1):
        store.append(
            AgentActivityEvent(
                event_id=f"demo-pagination-event-{number:03d}",
                analysis_id=analysis_id,
                workspace_id="demo-workspace",
                commit_id="synthetic-demo-data",
                hypothesis_id=f"DEMO-H-{number:03d}",
                stage="DEMO_PAGINATION",
                agent_role="DEMO Agent",
                attempt_id=f"demo-attempt-{number:03d}",
                sequence=number,
                kind=ActivityKind.STAGE_COMPLETED,
                status="SUCCEEDED",
                summary_ko=f"DEMO 전용 로그 {number} · 실제 분석 이벤트가 아닙니다.",
                started_at=datetime(2026, 10, 10, tzinfo=UTC)
                + timedelta(seconds=number),
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-data-dir", type=Path, required=True)
    parser.add_argument("--output-data-dir", type=Path, required=True)
    parser.add_argument("--items", type=int, default=23)
    parser.add_argument("--logs", type=int, default=25)
    parser.add_argument("--histories", type=int, default=14)
    args = parser.parse_args()
    if args.output_data_dir.exists():
        raise SystemExit("output data directory already exists; refusing to overwrite")
    if min(args.items, args.logs, args.histories) < 1:
        raise SystemExit("positive fixture sizes required")
    shutil.copytree(args.source_data_dir, args.output_data_dir)
    query = DashboardQuery(args.output_data_dir)
    analysis_id = query.list_analyses()[0].analysis_id
    marker, pages = collect_source_pages(query, analysis_id)
    model = DashboardReadModel(args.output_data_dir)
    model.initialize()
    counts = model.replace(analysis_id, marker, _expand_pages(pages, args.items))
    _duplicate_histories(model.database, analysis_id, args.histories)
    _seed_logs(model.database, analysis_id, args.logs)
    print(
        json.dumps(
            {
                "demo": True,
                "data_dir": str(args.output_data_dir.resolve()),
                "analysis_id": analysis_id,
                "list_counts": counts,
                "logs": args.logs,
                "repository_history": args.histories,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
