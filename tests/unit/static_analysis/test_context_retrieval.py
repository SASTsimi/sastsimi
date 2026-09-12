from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeFact,
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    CodeWorkspace,
    ContextRetrievalLimits,
    StaticFactBundle,
    ToolSource,
)
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.context import (
    ContextCeilingProfile,
    ContextReadPlan,
    ContextRetrievalIntent,
)
from sastsimi.ports.dto import MonotonicActionDeadline, TrackedFile
from sastsimi.static_analysis.context_retrieval import (
    plan_context_retrieval,
    read_context_files,
)


def _ref(kind: str, value: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": value,
            "data_kind": kind,
            "record_id": value if kind != "artifact" else None,
            "content_hash": "a" * 64 if kind != "artifact" else value,
            "workspace_id": "ws1",
            "commit_id": "c1",
        }
    )


def _location(path: str, line: int, end: int | None = None) -> CodeLocation:
    return CodeLocation.model_validate(
        {
            "workspace_id": "ws1",
            "commit_id": "c1",
            "file_path": path,
            "start_line": line,
            "start_column": None,
            "end_line": end or line,
            "end_column": None,
        }
    )


def _symbol(name: str, path: str, line: int, end: int | None = None) -> CodeSymbol:
    return CodeSymbol.model_validate(
        {
            "symbol_id": name,
            "symbol_kind": "CALLABLE",
            "native_kind": "function",
            "name": name,
            "location": _location(path, line, end),
        }
    )


def _source() -> ToolSource:
    return ToolSource.model_validate(
        {
            "attempt_id": "static-attempt",
            "tool_name": "AST",
            "tool_version": "1",
            "rule_id": None,
            "raw_result_ref": _ref("artifact", "b" * 64),
        }
    )


def _relation(
    relation_id: str, kind: str, source: CodeSymbol, target: CodeSymbol
) -> CodeRelation:
    return CodeRelation.model_validate(
        {
            "relation_id": relation_id,
            "relation_kind": kind,
            "from_symbol_id": source.symbol_id,
            "from_location": source.location,
            "to_symbol_id": target.symbol_id,
            "to_location": target.location,
            "producer": _source(),
        }
    )


def _fact(fact_id: str, kind: str, symbol: CodeSymbol) -> CodeFact:
    return CodeFact.model_validate(
        {
            "fact_id": fact_id,
            "fact_kind": kind,
            "symbol_id": symbol.symbol_id,
            "location": symbol.location,
            "producer": _source(),
        }
    )


def _fixture() -> tuple[StaticFactBundle, dict[str, CodeSymbol]]:
    symbols = {
        "caller": _symbol("caller", "src/caller.py", 1, 5),
        "seed": _symbol("seed", "src/seed.py", 10, 30),
        "callee": _symbol("callee", "src/callee.py", 1, 20),
        "guarded": _symbol("guarded", "src/guarded.py", 1, 20),
        "route": CodeSymbol.model_validate(
            {
                "symbol_id": "route",
                "symbol_kind": "ROUTE",
                "native_kind": "route",
                "name": "route",
                "location": _location("src/routes.py", 2),
            }
        ),
    }
    relations = (
        _relation("call-in", "CALL", symbols["caller"], symbols["seed"]),
        _relation("call-out", "CALL", symbols["seed"], symbols["callee"]),
        _relation("call-guard", "CALL", symbols["seed"], symbols["guarded"]),
    )
    bundle = StaticFactBundle.model_construct(
        meta=RecordMeta.model_validate(
            {
                "record_id": "bundle-r1",
                "logical_record_id": "bundle-l1",
                "record_type": "static_fact_bundle",
                "schema_version": "1.0.0",
                "analysis_id": "a1",
                "workspace_id": "ws1",
                "commit_id": "c1",
                "hypothesis_id": None,
                "attempt_id": None,
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": datetime(2026, 9, 11, tzinfo=UTC),
            }
        ),
        entities=tuple(symbols.values()),
        locations=tuple(symbol.location for symbol in symbols.values()),
        source_candidates=(_fact("source", "SOURCE", symbols["caller"]),),
        sink_candidates=(_fact("sink", "SINK", symbols["callee"]),),
        sanitizer_candidates=(),
        validator_candidates=(),
        auth_and_permission_checks=(_fact("guard", "AUTH_CHECK", symbols["guarded"]),),
        other_facts=(),
        call_edges=relations,
        data_flow_candidates=(
            _relation("flow", "DATA_FLOW", symbols["seed"], symbols["callee"]),
        ),
        route_bindings=(
            _relation("route-bind", "ROUTE_BINDING", symbols["route"], symbols["seed"]),
        ),
        tool_runs=(),
        gaps=(),
        errors=(),
    )
    return bundle, symbols


def _work() -> WorkExecutionState:
    return WorkExecutionState.model_construct(
        meta=RecordMeta.model_validate(
            {
                "record_id": "work-r1",
                "logical_record_id": "work-l1",
                "record_type": "work_execution_state",
                "schema_version": "1.0.0",
                "analysis_id": "a1",
                "workspace_id": "ws1",
                "commit_id": "c1",
                "hypothesis_id": "h1",
                "attempt_id": None,
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": datetime(2026, 9, 11, tzinfo=UTC),
            }
        ),
        work_id="work1",
        parent_work_ref=None,
        work_type=WorkType.CONTEXT_RETRIEVAL,
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        work_generation=1,
        status=WorkStatus.RUNNING,
        state_version=3,
        last_transition_ref=None,
        last_transition_commit_ref=None,
        active_attempt_id="ctx-attempt",
        input_hash="c" * 64,
        dedupe_key="d" * 64,
        trigger_primitive_ref=None,
        input_refs=(),
        output_refs=(),
        gap_ids=(),
        error_ids=(),
        waiting_for=(),
        stop_reason=None,
        started_at=datetime(2026, 9, 11, tzinfo=UTC),
        finished_at=None,
        elapsed_ms=0,
    )


def _workspace() -> CodeWorkspace:
    return CodeWorkspace.model_validate(
        {
            "meta": RunMeta.model_validate(
                {
                    "record_id": "workspace-r1",
                    "logical_record_id": "workspace-l1",
                    "record_type": "code_workspace",
                    "schema_version": "1.0.0",
                    "analysis_id": "a1",
                    "revision_number": 1,
                    "previous_record_id": None,
                    "created_at": datetime(2026, 9, 11, tzinfo=UTC),
                }
            ),
            "workspace_id": "ws1",
            "analysis_id": "a1",
            "repository_url": "https://example.invalid/repo.git",
            "commit_id": "c1",
            "status": "READY",
        }
    )


def _plan(query: str | None, seed: CodeSymbol, *, depth: int = 1) -> ContextReadPlan:
    bundle, _ = _fixture()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    limits = ContextRetrievalLimits.model_construct(
        max_depth=depth,
        max_fragments=20,
        max_bytes=100_000,
        max_requests_per_hypothesis=3,
        timeout_ms=2_000,
    )
    return plan_context_retrieval(
        intent=ContextRetrievalIntent(
            proposal_ref=_ref("hypothesis_proposal", "proposal-r1"),
            bundle_ref=bundle_ref,
            requested_entities=(seed,),
            requested_locations=(),
            relation_query=() if query is None else (query,),  # type: ignore[arg-type]
            reason="Need exact context",
            requested_limits=limits,
        ),
        bundle=bundle,
        workspace=_workspace(),
        work=_work(),
        ceilings=ContextCeilingProfile(_ref("artifact", "e" * 64), limits),
        work_timeout_ms=2_000,
    )


@pytest.mark.parametrize(
    ("query", "seed_name", "relation_ids"),
    [
        ("CALLERS", "seed", ("call-in",)),
        ("CALLEES", "seed", ("call-guard", "call-out")),
        ("DATA_FLOW_NEIGHBORS", "seed", ("flow",)),
        ("AUTH_GUARDS", "seed", ("call-guard",)),
        ("ROUTE_BINDINGS", "seed", ("route-bind",)),
    ],
)
def test_plan_uses_only_declared_relation_semantics(
    query: str, seed_name: str, relation_ids: tuple[str, ...]
) -> None:
    _, symbols = _fixture()
    plan = _plan(query, symbols[seed_name])

    assert tuple(item.relation_id for item in plan.relations) == relation_ids
    assert plan.file_paths == tuple(sorted(set(plan.file_paths)))


def test_seed_only_uses_empty_relation_query() -> None:
    _, symbols = _fixture()
    plan = _plan(None, symbols["seed"])

    assert plan.relations == ()
    assert plan.entities == (symbols["seed"],)


def test_requested_limit_above_ceiling_fails_before_any_file_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, symbols = _fixture()
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    requested = ContextRetrievalLimits(
        max_depth=2,
        max_fragments=2,
        max_bytes=100,
        max_requests_per_hypothesis=1,
        timeout_ms=100,
    )
    ceiling = requested.model_copy(update={"max_depth": 1})
    monkeypatch.setattr(Path, "open", lambda *_a, **_k: pytest.fail("file opened"))

    with pytest.raises(ValueError, match="CONTEXT_LIMIT_EXCEEDED"):
        plan_context_retrieval(
            intent=ContextRetrievalIntent(
                proposal_ref=_ref("hypothesis_proposal", "proposal-r1"),
                bundle_ref=bundle_ref,
                requested_entities=(symbols["seed"],),
                requested_locations=(),
                relation_query=("CALLEES",),
                reason="Need exact context",
                requested_limits=requested,
            ),
            bundle=bundle,
            workspace=_workspace(),
            work=_work(),
            ceilings=ContextCeilingProfile(_ref("artifact", "e" * 64), ceiling),
            work_timeout_ms=100,
        )


def test_reader_returns_only_authorized_tracked_range() -> None:
    root = Path(__file__).parents[3]
    source = Path(__file__)
    git_path = source.relative_to(root).as_posix()
    location = _location(git_path, 1)
    _, symbols = _fixture()
    original = _plan("CALLERS", symbols["seed"])
    limits = original.requested_limits.model_copy(
        update={"max_bytes": source.stat().st_size}
    )
    plan = replace(
        original,
        requested_limits=limits,
        entities=(),
        locations=(location,),
        relations=(),
        file_paths=(git_path,),
    )
    deadline = MonotonicActionDeadline("read", 0, 1_000_000_000)

    result = read_context_files(
        plan=plan,
        workspace_root=root,
        tracked_files=(
            TrackedFile(git_path, "100644", "0" * 40, source.stat().st_size),
        ),
        deadline=deadline,
        monotonic_ns=lambda: 1,
    )

    assert result.returned_bytes == len(result.fragments[0].data)
    assert result.fragments[0].data == b"from __future__ import annotations\n"
    assert not result.truncated


@pytest.mark.parametrize(
    "git_path",
    (
        ".npmrc",
        "config/service-account.json",
        "maven/settings.xml",
    ),
)
def test_reader_rejects_sensitive_tracked_path_before_read(
    tmp_path: Path, git_path: str
) -> None:
    candidate = tmp_path.joinpath(*git_path.split("/"))
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("credential material", encoding="utf-8")
    location = _location(git_path, 1)
    _, symbols = _fixture()
    original = _plan("CALLERS", symbols["seed"])
    plan = replace(
        original,
        entities=(),
        locations=(location,),
        relations=(),
        file_paths=(git_path,),
    )

    with pytest.raises(ValueError, match="CONTEXT_PATH_SENSITIVE"):
        read_context_files(
            plan=plan,
            workspace_root=tmp_path,
            tracked_files=(
                TrackedFile(
                    git_path,
                    "100644",
                    "0" * 40,
                    candidate.stat().st_size,
                ),
            ),
            deadline=MonotonicActionDeadline("read", 0, 1_000_000_000),
            monotonic_ns=lambda: 1,
        )


def test_reader_rejects_untracked_path_before_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, symbols = _fixture()
    plan = _plan("CALLERS", symbols["seed"])
    monkeypatch.setattr(Path, "open", lambda *_a, **_k: pytest.fail("file opened"))

    with pytest.raises(ValueError, match="CONTEXT_PATH_UNTRACKED"):
        read_context_files(
            plan=plan,
            workspace_root=Path(__file__).parents[3],
            tracked_files=(),
            deadline=MonotonicActionDeadline("read", 0, 1_000_000_000),
            monotonic_ns=lambda: 1,
        )


def test_expired_deadline_opens_no_file(monkeypatch: pytest.MonkeyPatch) -> None:
    _, symbols = _fixture()
    plan = _plan("CALLERS", symbols["seed"])
    monkeypatch.setattr(Path, "open", lambda *_a, **_k: pytest.fail("file opened"))

    result = read_context_files(
        plan=plan,
        workspace_root=Path(__file__).parents[3],
        tracked_files=(),
        deadline=MonotonicActionDeadline("read", 0, 1),
        monotonic_ns=lambda: 2,
    )

    assert result.truncated and result.fragments == ()
