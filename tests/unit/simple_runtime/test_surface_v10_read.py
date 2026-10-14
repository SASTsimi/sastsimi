"""Read replay of a v10 successor after it replaces the live v9 terminal."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.simple_runtime.models import input_reference_hash
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_coverage_v7_read import verified_saved_coverage_v7
from sastsimi.simple_runtime.surface_coverage_v8 import evaluate_surface_coverage_v8
from sastsimi.simple_runtime.surface_enrichment_v10 import (
    prepare_surface_enrichment_v10,
    v9_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_proof_read import verified_surface_coverage_counts
from sastsimi.simple_runtime.surface_route_boundary_v10 import (
    prove_route_boundaries_v10,
)
from tests.unit.simple_runtime.test_surface_v9_read import _saved_v9_case


def test_v9_replay_uses_saved_predecessor_after_live_terminal_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A v10 promotion must not make its pinned v9 parent unreadable."""

    case = _saved_v9_case(tmp_path, monkeypatch)
    store = case["store"]
    v9_terminal = store.run.candidate_terminal
    v9_root = store.get()
    assert v9_terminal is not None
    successor_ref = case["artifacts"].put_json({"successor": True})
    store.run = store.run.model_copy(
        update={
            "candidate_terminal": v9_terminal.model_copy(
                update={
                    "surface_proof_version": 8,
                    "surface_coverage_hash": successor_ref.content_hash,
                }
            )
        }
    )
    successor_root = v9_root.model_copy(
        update={"output_refs": (v9_root.output_refs[0], successor_ref)}
    )
    store.get = lambda *_args: successor_root

    verified = verified_saved_coverage_v7(
        case["identity"],
        case["index"],
        case["coverage_ref"],
        cast(SimpleCheckpointStore, store),
        case["artifacts"],
        predecessor_terminal=v9_terminal,
        predecessor_root=v9_root,
    )
    assert verified == case["proof"]


def _saved_v10_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Build a real, pinned v9-to-v10 fixture with a replaced live root."""

    case = _saved_v9_case(tmp_path, monkeypatch)
    index = case["index"]
    identity = case["identity"]
    store = case["store"]
    artifacts = case["artifacts"]
    graph = case["graph"]
    certificate = case["path_certificate"]
    v9_plan = json.loads(artifacts.read(case["v9_plan_ref"]))
    proofs = prove_route_boundaries_v10(
        index,
        case["workspace"],
        {"surface-1": graph},
        {"surface-1": certificate},
    )
    for proof in proofs.values():
        artifacts.put_json(proof.to_json())
    plan = prepare_surface_enrichment_v10(
        identity,
        index,
        case["proof"],
        case["v9_plan_ref"],
        case["coverage_ref"],
        case["v9_terminal"],
        v9_progress_snapshot_hash(v9_plan, case["progress"]),
        proofs,
        v9_root=case["v9_root"],
    )
    plan_ref = artifacts.put_json(plan)
    coverage = evaluate_surface_coverage_v8(
        index,
        case["proof"],
        plan_ref,
        proofs,
        pending_candidate_count=0,
        pending_child_count=0,
    )
    coverage_ref = artifacts.put_json(coverage.to_json())
    counts = {
        status: sum(row.coverage_status == status for row in coverage.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    successor_terminal = case["v9_terminal"].model_copy(
        update={
            "status": "COMPLETE" if coverage.complete else "PARTIAL",
            "surface_proof_version": 8,
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": counts,
        }
    )
    store.run = store.run.model_copy(
        update={
            "candidate_terminal": successor_terminal,
            "surface_enrichment_v10_plan_ref": plan_ref,
        }
    )
    root = case["v9_root"]
    successor_root = root.model_copy(
        update={"output_refs": (root.output_refs[0], coverage_ref)}
    )
    store.get = lambda *_args: successor_root
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v8_read.recompute_v9_runtime_evidence",
        lambda *_args: (
            None,
            {},
            {"surface-1": certificate},
            {"surface-1": graph},
            {},
        ),
    )
    return {
        "identity": identity,
        "index": index,
        "store": store,
        "artifacts": artifacts,
        "workspace": case["workspace"],
        "coverage": coverage,
        "coverage_ref": coverage_ref,
        "terminal": successor_terminal,
        "counts": counts,
        "progress": case["progress"],
    }


def test_v10_read_replays_parent_and_successor_from_pinned_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live v8 terminal is displayable only after replay of v9 and v10."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _saved_v10_case(tmp_path, monkeypatch)

    verified = verified_saved_coverage_v8(
        case["identity"],
        case["index"],
        case["coverage_ref"],
        cast(SimpleCheckpointStore, case["store"]),
        case["artifacts"],
    )
    assert verified == case["coverage"]
    read_counts = verified_surface_coverage_counts(
        case["coverage"].to_json(),
        case["index"],
        case["terminal"],
        artifacts=case["artifacts"],
        coverage_ref=case["coverage_ref"],
        store=cast(SimpleCheckpointStore, case["store"]),
    )
    assert read_counts is not None
    assert read_counts["INSUFFICIENT"] == case["counts"]["INSUFFICIENT"]
    assert read_counts["TEMPLATE_CONTENT_NOT_ANALYZED_COUNT"] == sum(
        row.external_scope_limit == "TEMPLATE_CONTENT_NOT_ANALYZED"
        for row in case["coverage"].surfaces
    )
    omitted_route_gaps = case["coverage"].to_json()
    omitted_route_gaps.pop("remaining_route_gap_events")
    assert (
        verified_surface_coverage_counts(
            omitted_route_gaps,
            case["index"],
            case["terminal"],
            artifacts=case["artifacts"],
            coverage_ref=case["coverage_ref"],
            store=cast(SimpleCheckpointStore, case["store"]),
        )
        is None
    )


def test_v10_read_rejects_changed_v9_progress_after_successor_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later edit to the parent review ledger must not retain v10 counts."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _saved_v10_case(tmp_path, monkeypatch)
    progress = case["progress"]
    key = next(iter(progress))
    progress[key] = replace(progress[key], context_hash="0" * 64)
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )


@pytest.mark.parametrize(
    "changed_field", ["input_refs", "attempt_number", "error_code"]
)
def test_v10_read_rejects_mutated_live_root_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_field: str
) -> None:
    """Only output refs and timestamp may change when v10 replaces the v9 root."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _saved_v10_case(tmp_path, monkeypatch)
    store = case["store"]
    root = store.get()
    if changed_field == "input_refs":
        new_ref = case["artifacts"].put_json({"changed": True})
        new_refs = (*root.input_refs, new_ref)
        changed = root.model_copy(
            update={
                "input_refs": new_refs,
                "input_hash": input_reference_hash(new_refs),
            }
        )
    elif changed_field == "attempt_number":
        changed = root.model_copy(update={"attempt_number": root.attempt_number + 1})
    else:
        changed = root.model_copy(update={"error_code": "MUTATED"})
    store.get = lambda *_args: changed

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, store),
            case["artifacts"],
        )


def test_v10_read_rejects_changed_python_source_after_successor_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pinned source mismatch must suppress even a previously saved proof."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _saved_v10_case(tmp_path, monkeypatch)
    source = case["workspace"] / "app.py"
    source.write_bytes(source.read_bytes() + b"\n# changed\n")
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )


def _complete_static_partial_v10_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Isolate terminal binding with a complete V8 proof and partial static run."""

    case = _saved_v10_case(tmp_path, monkeypatch)
    original = case["coverage"]
    coverage = replace(
        original,
        surfaces=(
            replace(
                original.surfaces[0],
                coverage_status="COVERED",
                unresolved_reason_codes=(),
            ),
        ),
        effective_python_gaps=(),
        missing_v9_parts=(),
        remaining_route_gap_events=(),
    )
    assert coverage.complete
    coverage_ref = case["artifacts"].put_json(coverage.to_json())
    counts = {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0}
    terminal = case["terminal"].model_copy(
        update={
            "status": "PARTIAL",
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": counts,
        }
    )
    store = case["store"]
    store.run = store.run.model_copy(
        update={"static_disposition": "PARTIAL", "candidate_terminal": terminal}
    )
    root = store.get()
    store.get = lambda *_args: root.model_copy(
        update={"output_refs": (root.output_refs[0], coverage_ref)}
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v8_read.evaluate_surface_coverage_v8",
        lambda *_args, **_kwargs: coverage,
    )
    case.update(coverage=coverage, coverage_ref=coverage_ref, terminal=terminal)
    return case


def test_v10_read_accepts_complete_surface_with_partial_static_disposition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete surface proof cannot turn a partial static run complete."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _complete_static_partial_v10_case(tmp_path, monkeypatch)
    assert (
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )
        == case["coverage"]
    )
    counts = verified_surface_coverage_counts(
        case["coverage"].to_json(),
        case["index"],
        case["terminal"],
        artifacts=case["artifacts"],
        coverage_ref=case["coverage_ref"],
        store=cast(SimpleCheckpointStore, case["store"]),
    )
    assert counts is not None
    assert counts["COVERED"] == 1


def test_v10_read_rejects_false_complete_for_partial_static_disposition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _complete_static_partial_v10_case(tmp_path, monkeypatch)
    store = case["store"]
    forged = case["terminal"].model_copy(update={"status": "COMPLETE"})
    store.run = store.run.model_copy(update={"candidate_terminal": forged})
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, store),
            case["artifacts"],
        )
    assert (
        verified_surface_coverage_counts(
            case["coverage"].to_json(),
            case["index"],
            forged,
            artifacts=case["artifacts"],
            coverage_ref=case["coverage_ref"],
            store=cast(SimpleCheckpointStore, store),
        )
        is None
    )
    store.run = store.run.model_copy(update={"candidate_terminal": case["terminal"]})
    assert (
        verified_surface_coverage_counts(
            case["coverage"].to_json(),
            case["index"],
            forged,
            artifacts=case["artifacts"],
            coverage_ref=case["coverage_ref"],
            store=cast(SimpleCheckpointStore, store),
        )
        is None
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("decision_counts", {"SKIPPED": 1}),
        ("deep_counts", {"DONE": 1}),
        ("hypothesis_count", 1),
        ("chaining_pool_fingerprint", "f" * 64),
        ("chaining_batch_count", 1),
    ),
)
def test_v10_read_rejects_changed_inherited_terminal_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    """Only the five V10 promotion fields may differ from pinned V9."""

    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )

    case = _saved_v10_case(tmp_path, monkeypatch)
    store = case["store"]
    forged = case["terminal"].model_copy(update={field: value})
    store.run = store.run.model_copy(update={"candidate_terminal": forged})
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, store),
            case["artifacts"],
        )
