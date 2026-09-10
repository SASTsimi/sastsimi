from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.fake_setup import FakeSetupDependencies, FakeSetupStages
from sastsimi.orchestration.static_publication import (
    StaticAttemptPublisher,
    StaticNormalizationPublisher,
    StaticNormalizationSource,
)
from sastsimi.ports.dto import (
    CandidateError,
    CandidateGap,
    CandidateRule,
    StaticToolObservation,
    StaticToolRequest,
)
from sastsimi.runtime.fake_support import ANALYSIS_ID
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.normalizer import StaticNormalizer, decoder_key
from tests.unit.static_analysis.test_normalizer import _material, meta


def test_decoder_registry_key_requires_full_record_identity() -> None:
    artifact = StoredDataRef(
        stored_data_id=StoredDataId("a" * 64),
        data_kind="artifact",
        record_id=None,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )

    with pytest.raises(ValueError, match="STATIC_DECODER_PROFILE_INVALID"):
        decoder_key(artifact, "AST", "1")


def test_normalization_sources_are_set_equal_including_failed_tool_work() -> None:
    first = StoredDataRef(
        stored_data_id=StoredDataId("a" * 64),
        data_kind="work_execution_state",
        record_id=RecordId("tool-work-a"),
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    failed = first.model_copy(
        update={
            "stored_data_id": StoredDataId("b" * 64),
            "record_id": RecordId("tool-work-failed"),
            "content_hash": "b" * 64,
        }
    )

    with pytest.raises(ValueError, match="STATIC_NORMALIZATION_PUBLICATION_INVALID"):
        StaticNormalizationPublisher._validate_source_set((first, failed), (first,))

    StaticNormalizationPublisher._validate_source_set((first, failed), (failed, first))


def test_candidate_bundle_is_fully_validated_before_complete() -> None:
    material, observation = _material()
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
    normalizer = StaticNormalizer(
        {
            decoder_key(
                material.profile_ref,
                material.result.tool_name,
                material.result.tool_version,
            ): lambda raw, result, profile, catalog: observation
        }
    )
    valid = normalizer.normalize(
        bundle_meta=bundle_meta,
        workspace=workspace,
        materials=(material,),
    )
    invalid = valid.model_copy(update={"tool_runs": ()})
    config_ref = StoredDataRef(
        stored_data_id=StoredDataId("c" * 64),
        data_kind="analysis_configuration",
        record_id=None,
        content_hash="c" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    work = cast(
        WorkExecutionState,
        SimpleNamespace(
            work_id="normalize-work",
            meta=RecordMeta.model_validate_json(
                canonical_bytes(meta("work_execution_state", attempt=None))
            ),
            status="RUNNING",
            work_type="STATIC_NORMALIZE",
            active_attempt_id="normalize-attempt",
            input_hash="f" * 64,
            input_refs=(config_ref,),
        ),
    )
    completed: list[StaticFactBundle] = []
    runner = cast(
        WorkflowRunner,
        SimpleNamespace(
            runtime=SimpleNamespace(work=SimpleNamespace(get=lambda _work_id: work)),
            metadata=lambda _meta, _kind: bundle_meta.model_dump(),
            complete=lambda _work, _identity, _role, outputs, **_values: (
                completed.append(outputs[0])
            ),
        ),
    )
    publisher = StaticNormalizationPublisher(
        runner,
        cast(StaticNormalizer, SimpleNamespace(normalize=lambda **_values: invalid)),
    )
    dynamic = cast(Any, publisher)
    dynamic._validate_workspace_and_sources = lambda *_values: None
    dynamic._resolve_source = lambda *_values: material
    dynamic._current_running_attempt = lambda _work: SimpleNamespace(
        input_hash="f" * 64
    )
    source = StaticNormalizationSource(
        tool_work_ref=StoredDataRef(
            stored_data_id=StoredDataId("e" * 64),
            data_kind="work_execution_state",
            record_id=RecordId("tool-work"),
            content_hash="a" * 64,
            workspace_id=WorkspaceId("ws1"),
            commit_id=CommitId("c1"),
        ),
        profile_ref=material.profile_ref,
        analysis_config_ref=config_ref,
    )

    with pytest.raises(ValueError, match="STATIC_NORMALIZATION_PUBLICATION_INVALID"):
        publisher.publish(
            work,
            config_ref,
            workspace,
            (source,),
        )

    assert completed == []
    assert reference(valid) != reference(invalid)


@pytest.mark.parametrize(
    ("ast_status", "rule_status", "all_unusable"),
    (
        ("PARTIAL", "SUCCEEDED", False),
        ("SUCCEEDED", "FAILED", False),
        ("FAILED", "FAILED", True),
    ),
)
def test_real_runtime_publication_and_terminal_replay_validate_expected_runs(
    tmp_path: Path,
    ast_status: str,
    rule_status: str,
    all_unusable: bool,
) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    scenario = cast(Any, pipeline)._scenario
    setup = FakeSetupStages(
        FakeSetupDependencies(
            data_dir=tmp_path,
            runtime_builder=scenario.runtime_builder,
            database_upgrader=scenario.database_upgrader,
            provider_invoke=scenario.provider_invoke,
            provider_probe=scenario.provider_probe,
            policy_fetch=scenario.policy_fetch,
            clock=scenario.clock,
            ids=scenario.ids,
            evidence=scenario.evidence,
            records=scenario.records,
        )
    )
    scope, _, orchestrator = setup._bootstrap()
    assert setup.runtime is not None and setup.runner is not None
    runtime, runner = setup.runtime, setup.runner
    run_state = runtime.budget_registry.current_state(str(ANALYSIS_ID))
    assert run_state.workspace_ref is not None
    workspace = runtime.unit_of_work.records.get_exact(run_state.workspace_ref)
    assert isinstance(workspace, CodeWorkspace)
    workspace_ref = reference(workspace)
    profile_refs = (
        setup._static_tool_profile(
            adapter_key="PYTHON_AST", tool_name="AST", tool_kind="STRUCTURE"
        ),
        setup._static_tool_profile(
            adapter_key="OPENGREP", tool_name="OPENGREP", tool_kind="RULE_BASED"
        ),
    )
    config_ref = setup._stored_artifact("normalization-config")
    catalog_ref = setup._stored_artifact("normalization-catalog")
    works = (
        runner.start(
            scope,
            setup._record_meta("static_tool_stage"),
            "STATIC_TOOL",
            "ANALYSIS",
            str(workspace.analysis_id),
            orchestrator,
            inputs=(workspace_ref, profile_refs[0], config_ref),
        ),
        runner.start(
            scope,
            setup._record_meta("static_tool_stage"),
            "STATIC_TOOL",
            "ANALYSIS",
            str(workspace.analysis_id),
            orchestrator,
            inputs=(workspace_ref, profile_refs[1], config_ref, catalog_ref),
        ),
    )
    static_identity = setup.evidence.identity(RequesterRole.STATIC_ANALYSIS)
    attempt_publisher = StaticAttemptPublisher(
        runner,
        {catalog_ref: ("fake-rule",)},
        {catalog_ref: ("fake-rule",)},
    )
    outputs = []
    observations_by_tool: dict[str, StaticToolObservation] = {}
    for work, profile_ref, tool_name, tool_kind in zip(
        works,
        profile_refs,
        ("AST", "OPENGREP"),
        ("STRUCTURE", "RULE_BASED"),
        strict=True,
    ):
        action = runner.action(
            work,
            static_identity,
            "STATIC_ANALYSIS",
            "RUN_TOOL",
            tool_name=tool_name,
            file_paths=("src/app.py",),
        )
        status = ast_status if tool_name == "AST" else rule_status
        partial = status == "PARTIAL"
        failed = status == "FAILED"
        gap = CandidateGap(
            "STATIC_ANALYSIS",
            "STATIC_TOOL_FAILED" if failed else "STATIC_COVERAGE_MISSING",
            "FAILED" if failed else "UNSUPPORTED",
            "fixture tool failure" if failed else "fixture partial coverage",
            ("src/app.py",),
            ("Python",),
            (),
            False,
        )
        rules = (
            (CandidateRule("fake-rule", "SELECTED", "EXECUTED", 1, None, None),)
            if tool_kind == "RULE_BASED" and not failed
            else ()
        )
        observation = StaticToolObservation(
            tool_name=tool_name,
            tool_version="1",
            tool_kind=cast(Any, tool_kind),
            status=cast(Any, status),
            raw_output=None if failed else f"raw-{tool_name}".encode(),
            raw_media_type=None if failed else "application/octet-stream",
            analyzed_paths=() if partial or failed else ("src/app.py",),
            skipped_paths=("src/app.py",) if partial or failed else (),
            analyzed_languages=("Python",),
            skipped_languages=(),
            notes=("runtime fixture",),
            selected_rule_packs=("fake-security",) if rules else (),
            rules=rules,
            symbols=(),
            facts=(),
            relations=(),
            gaps=(gap,) if partial or failed else (),
            errors=(
                (
                    CandidateError(
                        "STATIC_ANALYSIS",
                        "STATIC_TOOL_FAILED",
                        "fixture tool failure",
                        False,
                    ),
                )
                if failed
                else ()
            ),
            started_monotonic_ms=1,
            finished_monotonic_ms=2,
        )
        published = attempt_publisher.publish(
            StaticToolRequest(
                action=action,
                workspace=workspace,
                tool_profile_ref=profile_ref,
                analysis_config_ref=config_ref,
                rule_catalog_ref=(catalog_ref if tool_kind == "RULE_BASED" else None),
            ),
            observation,
        )
        outputs.append((published.result, published.result_ref))
        observations_by_tool[tool_name] = observation
    tool_work_refs = tuple(
        reference(runtime.work.get(str(work.work_id))) for work in works
    )
    assert all(isinstance(item, StoredDataRef) for item in tool_work_refs)
    normalization = runner.start(
        scope,
        setup._record_meta("static_normalize"),
        "STATIC_NORMALIZE",
        "ANALYSIS",
        str(workspace.analysis_id),
        orchestrator,
        inputs=(workspace_ref, *tool_work_refs, config_ref, catalog_ref),
    )
    sources = (
        StaticNormalizationSource(
            cast(StoredDataRef, tool_work_refs[0]),
            profile_refs[0],
            config_ref,
        ),
        StaticNormalizationSource(
            cast(StoredDataRef, tool_work_refs[1]),
            profile_refs[1],
            config_ref,
            catalog_ref,
            ("fake-rule",),
        ),
    )
    decoders: dict[Any, Any] = {}
    for (result, _), profile_ref in zip(outputs, profile_refs, strict=True):
        if result.raw_result_ref is None:
            continue
        with runtime.unit_of_work.artifacts.open_verified(
            result.raw_result_ref
        ) as stream:
            raw = stream.read()
        observation = observations_by_tool[result.tool_name]
        assert observation.raw_output == raw
        decoders[decoder_key(profile_ref, result.tool_name, result.tool_version)] = (
            lambda raw, result, profile, catalog, observation=observation: observation
        )
    publisher = StaticNormalizationPublisher(runner, StaticNormalizer(decoders))

    if all_unusable:
        with pytest.raises(ValueError, match="STATIC_NORMALIZATION_NO_USABLE_INPUT"):
            publisher.publish(normalization, static_identity, workspace, sources)
        failed_work = runtime.work.get(str(normalization.work_id))
        assert failed_work.status == "FAILED"
        assert failed_work.output_refs == ()
        return

    bundle, bundle_ref = publisher.publish(
        normalization, static_identity, workspace, sources
    )
    terminal = runtime.work.get(str(normalization.work_id))
    assert bundle.tool_runs == tuple(
        sorted((item[0] for item in outputs), key=lambda item: item.tool_name)
    )
    assert terminal.output_refs == (bundle_ref,)
    committed_bundle = runtime.unit_of_work.records.get_exact(bundle_ref)
    assert committed_bundle == bundle
    replay_materials = tuple(
        publisher._resolve_source(terminal, workspace, source) for source in sources
    )
    assert publisher._expected_runs(replay_materials) == bundle.tool_runs
    assert publisher.publish(terminal, static_identity, workspace, sources) == (
        bundle,
        bundle_ref,
    )
    materials = tuple(
        publisher._resolve_source(terminal, workspace, source) for source in sources
    )
    damaged = bundle.model_copy(update={"tool_runs": bundle.tool_runs[:-1]})
    with pytest.raises(ValueError, match="STATIC_NORMALIZATION_PUBLICATION_INVALID"):
        publisher._validate_committed_bundle(
            terminal, workspace, damaged, bundle_ref, materials
        )
