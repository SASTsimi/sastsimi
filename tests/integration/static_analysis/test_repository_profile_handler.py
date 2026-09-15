"""Repository profiling reaches durable storage through the public handler."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import CapabilityControlEvidence
from sastsimi.contracts.refs import HostConfigurationRef, RunStoredDataRef, reference
from sastsimi.contracts.static import (
    CodeWorkspace,
    RepositoryExecutionSelection,
    RepositoryProfile,
)
from sastsimi.orchestration.fake_setup import FakeSetupDependencies, FakeSetupStages
from sastsimi.orchestration.repository_profile_handler import RepositoryProfileHandler
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    RepositoryPreparation,
    TrackedFile,
)
from sastsimi.runtime.fake_support import ANALYSIS_ID
from sastsimi.static_analysis.repository_profile import (
    RepositoryExecutionSelector,
    RepositoryProfiler,
)
from tests.unit.static_analysis.test_repository_profile import _Resolver


def _tracked(root: Path, path: str, raw: bytes) -> TrackedFile:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return TrackedFile(path, "100644", blob, len(raw))


class _Guard:
    calls = 0

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        assert subject_key == "git"
        assert expected_sha256 == "d" * 64

    async def assert_preparation_unchanged(
        self,
        outcome: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        assert outcome.status == "READY"
        assert deadline.action_id == "profile"
        assert attempt_id
        assert check_id in {
            "repository-profile-before",
            "repository-profile-after",
        }
        self.calls += 1
        return ()


def _registered_resolver(setup: FakeSetupStages) -> _Resolver:
    assert setup.runtime is not None
    cast(Any, setup.runtime.configuration.registry).capability_host_id = "host-a"
    raw_ref = setup.runtime.unit_of_work.artifacts.commit(
        setup.runtime.unit_of_work.artifacts.stage_bytes(
            b"trusted capability probe\n", "text/plain"
        )
    )
    resolver = _Resolver()
    registered = {}
    for route, selected in resolver.selections.items():
        capability_meta = selected.evidence.meta.model_copy(
            update={
                "workspace_id": raw_ref.workspace_id,
                "commit_id": raw_ref.commit_id,
            }
        )
        controls = tuple(
            CapabilityControlEvidence(
                control=item.control,
                evidence_ref=raw_ref,
            )
            for item in selected.evidence.security_control_evidence
        )
        evidence = selected.evidence.model_copy(
            update={
                "meta": capability_meta,
                "probe_evidence_refs": (raw_ref,),
                "security_control_evidence": controls,
            }
        )
        setup.evidence.capability_approvals.add(content_hash(evidence))
        evidence_ref = setup.runtime.configuration.register_capability_approval(
            evidence
        )
        profile = selected.profile.model_copy(
            update={
                "meta": selected.profile.meta.model_copy(
                    update={
                        "workspace_id": raw_ref.workspace_id,
                        "commit_id": raw_ref.commit_id,
                    }
                ),
                "capability_evidence_ref": evidence_ref,
            }
        )
        profile_ref = (
            setup.runtime.configuration.register_production_static_tool_profile(profile)
        )
        registered[route] = selected.model_copy(
            update={
                "profile": profile,
                "profile_ref": profile_ref,
                "evidence": evidence,
            }
        )
    resolver.selections = registered

    git_controls = tuple(
        CapabilityControlEvidence(control=item.control, evidence_ref=raw_ref)
        for item in resolver.git_evidence.security_control_evidence
    )
    git_evidence = resolver.git_evidence.model_copy(
        update={
            "meta": resolver.git_evidence.meta.model_copy(
                update={
                    "workspace_id": raw_ref.workspace_id,
                    "commit_id": raw_ref.commit_id,
                }
            ),
            "probe_evidence_refs": (raw_ref,),
            "security_control_evidence": git_controls,
        }
    )
    setup.evidence.capability_approvals.add(content_hash(git_evidence))
    git_evidence_ref = setup.runtime.configuration.register_capability_approval(
        git_evidence
    )
    resolver.git_profile = resolver.git_profile.model_copy(
        update={
            "meta": resolver.git_profile.meta.model_copy(
                update={
                    "workspace_id": raw_ref.workspace_id,
                    "commit_id": raw_ref.commit_id,
                }
            ),
            "capability_evidence_ref": git_evidence_ref,
        }
    )
    git_ref = setup.runtime.configuration.register_runtime_capability(
        resolver.git_profile
    )
    assert isinstance(git_ref, HostConfigurationRef)
    resolver.git_ref = git_ref
    resolver.pinned = {
        selected.profile_ref: selected.profile for selected in registered.values()
    } | {git_ref: resolver.git_profile}
    return resolver


@pytest.mark.asyncio
async def test_handler_publishes_profile_closed_over_ready_workspace(
    tmp_path: Path,
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
    state = setup.runtime.budget_registry.current_state(str(ANALYSIS_ID))
    assert isinstance(state.workspace_ref, RunStoredDataRef)
    workspace = setup.runtime.unit_of_work.records.get_exact(state.workspace_ref)
    assert isinstance(workspace, CodeWorkspace)
    workspace_ref = reference(workspace)
    assert isinstance(workspace_ref, RunStoredDataRef)

    root = tmp_path / "fake-workspace"
    tracked = (
        _tracked(root, "src/app.py", b"from fastapi import FastAPI\n"),
        _tracked(
            root,
            "pyproject.toml",
            b'[project]\nname="demo"\ndependencies=["fastapi"]\n',
        ),
        _tracked(root, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    preparation = RepositoryPreparation(
        analysis_id=str(workspace.analysis_id),
        workspace_id=str(workspace.workspace_id),
        repository_url=workspace.repository_url,
        requested_ref="fake",
        status="READY",
        resolved_commit_id=str(workspace.commit_id),
        root=root,
        tracked_files=tracked,
        gaps=(),
        errors=(),
        lease_id=root.name,
    )
    resolver = _registered_resolver(setup)
    git_refs = tuple(dict.fromkeys((resolver.git_ref, resolver.git_ref)))
    work = setup.runner.start(
        scope,
        setup._record_meta("repository_profile"),
        "REPOSITORY_PROFILE",
        "ANALYSIS",
        str(workspace.analysis_id),
        orchestrator,
        inputs=(workspace_ref, *git_refs),
    )
    guard = _Guard()
    published = await RepositoryProfileHandler(
        setup.runner,
        RepositoryProfiler(),
        RepositoryExecutionSelector(
            setup.runtime.configuration,
            operating_system="windows",
            architecture="x86_64",
        ),
        guard,
    ).execute(
        work=work,
        budget_scope=scope,
        identity=setup.evidence.identity(RequesterRole.STATIC_ANALYSIS),
        state_identity=orchestrator,
        workspace=workspace,
        workspace_ref=workspace_ref,
        preparation=preparation,
        git_clone_profile_ref=resolver.git_ref,
        git_checkout_profile_ref=resolver.git_ref,
        deadline=MonotonicActionDeadline(
            "profile",
            time.monotonic_ns(),
            time.monotonic_ns() + 1_000_000_000,
        ),
    )

    assert published.work.status == "SUCCEEDED"
    assert published.profile.status == "READY"
    assert published.profile_ref == reference(published.profile)
    assert guard.calls == 2
    stored = setup.runtime.unit_of_work.records.get_exact(published.profile_ref)
    assert isinstance(stored, RepositoryProfile)
    assert stored == published.profile
    selected = setup.runtime.unit_of_work.records.get_exact(published.selection_ref)
    assert isinstance(selected, RepositoryExecutionSelection)
    assert selected == published.selection
    decision = setup.runtime.unit_of_work.records.get_exact(
        published.profile.action_decision_ref
    )
    assert isinstance(decision, ActionDecision)
    assert decision.use_status == "USED"
    action = setup.runtime.unit_of_work.records.get_exact(decision.action_ref)
    assert isinstance(action, ActionRequest)
    assert action.action_type == "RUN_TOOL"
    assert action.tool_name == "repository-profiler"
    assert set(action.file_paths) == {item.git_path for item in tracked}

    drifted_work = setup.runner.start(
        scope,
        setup._record_meta("repository_profile"),
        "REPOSITORY_PROFILE",
        "ANALYSIS",
        str(workspace.analysis_id),
        orchestrator,
        generation=2,
        inputs=(workspace_ref, *git_refs),
    )
    (root / "src" / "app.py").write_text("print('changed')\n")
    with pytest.raises(ValueError, match="REPOSITORY_PROFILE_BLOCKED"):
        await RepositoryProfileHandler(
            setup.runner,
            RepositoryProfiler(),
            RepositoryExecutionSelector(
                setup.runtime.configuration,
                operating_system="windows",
                architecture="x86_64",
            ),
            guard,
        ).execute(
            work=drifted_work,
            budget_scope=scope,
            identity=setup.evidence.identity(RequesterRole.STATIC_ANALYSIS),
            state_identity=orchestrator,
            workspace=workspace,
            workspace_ref=workspace_ref,
            preparation=preparation,
            git_clone_profile_ref=resolver.git_ref,
            git_checkout_profile_ref=resolver.git_ref,
            deadline=MonotonicActionDeadline(
                "profile-drift",
                time.monotonic_ns(),
                time.monotonic_ns() + 1_000_000_000,
            ),
        )
    blocked = setup.runtime.work.get(str(drifted_work.work_id))
    assert blocked.status == "BLOCKED"
    assert blocked.active_attempt_id is None
    assert blocked.output_refs == ()
