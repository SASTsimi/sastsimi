from __future__ import annotations

import hashlib
from dataclasses import replace

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile, ToolRunResult
from sastsimi.ports.dto import (
    CandidateFact,
    CandidateLocation,
    CandidateRelation,
    CandidateSymbol,
    StaticToolObservation,
)
from sastsimi.static_analysis.normalizer import (
    StaticNormalizationInput,
    StaticNormalizer,
    decoder_key,
)


def meta(
    kind: str, *, attempt: str | None = "at1", run: bool = False
) -> dict[str, object]:
    value: dict[str, object] = {
        "record_id": f"{kind}-r1",
        "logical_record_id": f"{kind}-l1",
        "record_type": kind,
        "schema_version": "1.0.0",
        "analysis_id": "a1",
        "revision_number": 1,
        "previous_record_id": None,
        "created_at": "2026-09-08T00:00:00Z",
    }
    if not run:
        value.update(
            workspace_id="ws1",
            commit_id="c1",
            hypothesis_id=None,
            attempt_id=attempt,
        )
    return value


def _material() -> tuple[StaticNormalizationInput, StaticToolObservation]:
    raw = b'{"closed":"ast"}'
    raw_digest = hashlib.sha256(raw).hexdigest()
    profile = StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("static_tool_profile", attempt=None),
                "profile_key": "ast-fixture",
                "purpose": "FIXTURE",
                "status": "APPROVED",
                "adapter_key": "PYTHON_AST",
                "tool_name": "AST",
                "tool_kind": "STRUCTURE",
                "executable_key": "python",
                "executable_sha256": "a" * 64,
                "expected_version": "1",
                "capability_evidence_ref": None,
                "probe_timeout_ms": 100,
                "run_timeout_ms": 100,
                "stdout_limit_bytes": 1024,
                "stderr_limit_bytes": 1024,
                "max_attempt_output_bytes": 4096,
                "max_output_file_bytes": 2048,
                "max_artifact_read_bytes": 2048,
            }
        )
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    raw_ref = StoredDataRef(
        stored_data_id=StoredDataId(raw_digest),
        data_kind="artifact",
        record_id=None,
        content_hash=raw_digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    result = ToolRunResult.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("tool_run_result"),
                "tool_name": "AST",
                "tool_version": "1",
                "tool_kind": "STRUCTURE",
                "status": "SUCCEEDED",
                "coverage": {
                    "analyzed_paths": ["src/app.py"],
                    "skipped_paths": [],
                    "analyzed_languages": ["python"],
                    "skipped_languages": [],
                    "notes": [],
                },
                "rule_execution_ref": None,
                "raw_result_ref": raw_ref,
                "gaps": [],
                "errors": [],
                "started_at": "2026-09-08T00:00:00Z",
                "finished_at": "2026-09-08T00:00:00Z",
                "elapsed_ms": 0,
            }
        )
    )
    result_ref = reference(result)
    assert isinstance(result_ref, StoredDataRef)
    analysis_config_ref = StoredDataRef(
        stored_data_id=StoredDataId("c" * 64),
        data_kind="artifact",
        record_id=None,
        content_hash="c" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    location = CandidateLocation("src/app.py", 1, None, 3, None)
    observation = StaticToolObservation(
        tool_name="AST",
        tool_version="1",
        tool_kind="STRUCTURE",
        status="SUCCEEDED",
        raw_output=raw,
        raw_media_type="application/json",
        analyzed_paths=("src/app.py",),
        skipped_paths=(),
        analyzed_languages=("python",),
        skipped_languages=(),
        notes=(),
        selected_rule_packs=(),
        rules=(),
        symbols=(CandidateSymbol("handler", "CALLABLE", None, "handler", location),),
        facts=(CandidateFact("source", "SOURCE", "handler", location, None),),
        relations=(),
        gaps=(),
        errors=(),
        started_monotonic_ms=1,
        finished_monotonic_ms=2,
    )
    return (
        StaticNormalizationInput(
            result_ref=result_ref,
            result=result,
            profile_ref=profile_ref,
            profile=profile,
            analysis_config_ref=analysis_config_ref,
            rule_catalog_ref=None,
            raw_bytes=raw,
        ),
        observation,
    )


def test_normalization_is_deterministic_and_partitions_source() -> None:
    material, observation = _material()
    registry = {
        decoder_key(
            material.profile_ref,
            material.result.tool_name,
            material.result.tool_version,
        ): lambda raw, result, profile, catalog: observation
    }
    normalizer = StaticNormalizer(registry)
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )

    first = normalizer.normalize(
        bundle_meta=bundle_meta, workspace=workspace, materials=(material,)
    )
    second = normalizer.normalize(
        bundle_meta=bundle_meta, workspace=workspace, materials=(material,)
    )

    assert canonical_bytes(first) == canonical_bytes(second)
    assert len(first.entities) == 1
    assert len(first.source_candidates) == 1
    assert first.source_candidates[0].symbol_id == first.entities[0].symbol_id
    assert first.sink_candidates == ()


def test_normalization_reports_conflicting_source_identity() -> None:
    material, observation = _material()
    assert observation.symbols
    conflicting = replace(
        observation,
        symbols=(
            observation.symbols[0],
            replace(observation.symbols[0], name="different-name"),
        ),
    )
    normalizer = StaticNormalizer(
        {
            decoder_key(
                material.profile_ref,
                material.result.tool_name,
                material.result.tool_version,
            ): lambda raw, result, profile, catalog: conflicting
        }
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )

    bundle = normalizer.normalize(
        bundle_meta=bundle_meta, workspace=workspace, materials=(material,)
    )

    assert "STATIC_NORMALIZATION_CONFLICT" in {gap.code for gap in bundle.gaps}


def test_cross_observation_symbol_conflict_is_unresolved_and_order_invariant() -> None:
    first, first_observation = _material()
    raw = b'{"closed":"ast-second"}'
    raw_digest = hashlib.sha256(raw).hexdigest()
    raw_ref = StoredDataRef(
        stored_data_id=StoredDataId(raw_digest),
        data_kind="artifact",
        record_id=None,
        content_hash=raw_digest,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    result_data = first.result.model_dump(mode="json")
    result_data["meta"].update(
        record_id="tool-run-result-r2",
        logical_record_id="tool-run-result-l2",
        attempt_id="at2",
    )
    result_data["raw_result_ref"] = raw_ref.model_dump(mode="json")
    second_result = ToolRunResult.model_validate_json(canonical_bytes(result_data))
    second_ref = reference(second_result)
    assert isinstance(second_ref, StoredDataRef)
    second = replace(
        first,
        result_ref=second_ref,
        result=second_result,
        raw_bytes=raw,
    )
    assert first_observation.symbols
    second_observation = replace(
        first_observation,
        raw_output=raw,
        symbols=(replace(first_observation.symbols[0], name="other-handler"),),
    )
    normalizer = StaticNormalizer(
        {
            decoder_key(
                first.profile_ref,
                first.result.tool_name,
                first.result.tool_version,
            ): lambda value, result, profile, catalog: (
                first_observation if value == first.raw_bytes else second_observation
            )
        }
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )

    forward = normalizer.normalize(
        bundle_meta=bundle_meta,
        workspace=workspace,
        materials=(first, second),
    )
    reverse = normalizer.normalize(
        bundle_meta=bundle_meta,
        workspace=workspace,
        materials=(second, first),
    )

    assert canonical_bytes(forward) == canonical_bytes(reverse)
    assert {fact.symbol_id for fact in forward.source_candidates} == {None}
    assert "STATIC_NORMALIZATION_CONFLICT" in {gap.code for gap in forward.gaps}


def test_unresolved_data_flow_is_explicit_and_never_synthesizes_jump() -> None:
    material, observation = _material()
    source = CandidateLocation("src/app.py", 10, None, 10, None)
    sink = CandidateLocation("src/app.py", 30, None, 30, None)
    unresolved = replace(
        observation,
        relations=(
            CandidateRelation("flow-1", "DATA_FLOW", None, source, None, sink, None),
        ),
    )
    normalizer = StaticNormalizer(
        {
            decoder_key(
                material.profile_ref,
                material.result.tool_name,
                material.result.tool_version,
            ): lambda raw, result, profile, catalog: unresolved
        }
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )

    bundle = normalizer.normalize(
        bundle_meta=bundle_meta, workspace=workspace, materials=(material,)
    )

    assert len(bundle.data_flow_candidates) == 1
    assert bundle.data_flow_candidates[0].from_symbol_id is None
    assert bundle.data_flow_candidates[0].to_symbol_id is None
    assert "STATIC_DATA_FLOW_UNRESOLVED" in {gap.code for gap in bundle.gaps}


def test_data_flow_reduction_keeps_ordered_intermediate_path() -> None:
    material, observation = _material()
    first = CandidateLocation("src/app.py", 1, None, 1, None)
    middle = CandidateLocation("src/app.py", 2, None, 2, None)
    last = CandidateLocation("src/app.py", 3, None, 3, None)
    chained = replace(
        observation,
        relations=(
            CandidateRelation(
                "flow-1", "DATA_FLOW", "handler", first, "handler", middle, None
            ),
            CandidateRelation(
                "flow-2", "DATA_FLOW", "handler", middle, "handler", last, None
            ),
            CandidateRelation(
                "redundant-jump",
                "DATA_FLOW",
                "handler",
                first,
                "handler",
                last,
                None,
            ),
        ),
    )
    normalizer = StaticNormalizer(
        {
            decoder_key(
                material.profile_ref,
                material.result.tool_name,
                material.result.tool_version,
            ): lambda raw, result, profile, catalog: chained
        }
    )
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(
            {
                "meta": meta("code_workspace", run=True),
                "workspace_id": "ws1",
                "analysis_id": "a1",
                "repository_url": "https://example.invalid/repo",
                "commit_id": "c1",
                "status": "READY",
            }
        )
    )
    bundle_meta = RecordMeta.model_validate_json(
        canonical_bytes(meta("static_fact_bundle", attempt=None))
    )

    bundle = normalizer.normalize(
        bundle_meta=bundle_meta, workspace=workspace, materials=(material,)
    )

    assert len(bundle.data_flow_candidates) == 2
    assert {
        (edge.from_location.start_line, edge.to_location.start_line)
        for edge in bundle.data_flow_candidates
    } == {(1, 2), (2, 3)}
