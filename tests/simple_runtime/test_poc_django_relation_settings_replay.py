"""One source-bound replay after a generated relation-settings omission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime import stages
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import relation_settings_replay_binding
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_extract_exhaustion_replay import _exhausted_extract
from tests.unit.simple_runtime.test_django_relation_settings_omission import (
    _APP_SETTINGS,
    _CANDIDATE,
    _FAILURE,
    _MODELS,
    _PROJECT,
    _STDOUT,
)

_PINNED = {
    "project/config/settings.py": _PROJECT,
    "src/widget/settings.py": _APP_SETTINGS,
    "src/widget/models.py": _MODELS,
}
_DYNAMIC_CANDIDATE = _CANDIDATE.replace(
    b"    project_path = Path('/workspace/project/config/settings.py')\n"
    b"    project = literals(project_path)",
    b"    root = Path('/workspace')\n"
    b"    candidates = []\n"
    b"    for path in root.rglob('settings.py'):\n"
    b"        values = literals(path)\n"
    b"        apps = values.get('INSTALLED_APPS', ())\n"
    b"        if isinstance(apps, (list, tuple)) and 'widget' in apps:\n"
    b"            candidates.append((path, values))\n"
    b"    candidates.sort(key=lambda item: str(item[0]))\n"
    b"    project = candidates[0][1] if candidates else {}",
)


def _exhausted_relation_attempt(
    tmp_path: Path,
    *,
    extra_pinned: Mapping[str, bytes] | None = None,
    candidate_content: bytes = _CANDIDATE,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    workspace = tmp_path / "data" / "workspaces" / "workspace-1"
    workspace.mkdir(parents=True)
    pinned = {**_PINNED, **(extra_pinned or {})}
    for name, content in pinned.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(
        ("git", "init", "-q", str(workspace)), check=True, capture_output=True
    )
    subprocess.run(
        ("git", "-C", str(workspace), "add", "."),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@invalid.test",
            "commit",
            "-qm",
            "fixture",
        ),
        check=True,
        capture_output=True,
    )
    commit = subprocess.run(
        ("git", "-C", str(workspace), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        seed_commit_id=commit,
        stderr=_FAILURE,
        stdout=_STDOUT,
        execution_patch={"exit_code": 2},
        candidate_content=candidate_content,
    )
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    assert run.static_coverage_ref is not None
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_tracked_sources",
            "paths": sorted(pinned),
        }
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": exhausted.identity.analysis_id,
            "workspace_id": exhausted.identity.workspace_id,
            "commit_id": exhausted.identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "static_coverage_ref": run.static_coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": static_ref}))
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    static = store.require(root_identity, SimpleStage.STATIC_DONE)
    store.save_checkpoint(
        static.model_copy(
            update={
                "output_refs": (*static.output_refs, static_ref),
            }
        )
    )
    return store, artifacts, exhausted


def test_dynamic_relation_replay_rejects_conflicting_reachable_project(
    tmp_path: Path,
) -> None:
    conflicting = _PROJECT.replace(b"'false'", b"'true'")
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": conflicting},
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_literal_relation_replay_binds_its_exact_project_path(
    tmp_path: Path,
) -> None:
    candidate = _CANDIDATE.replace(
        b"project/config/settings.py", b"zother/config/settings.py"
    )
    conflicting = _PROJECT.replace(b"'false'", b"'true'")
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": conflicting},
        candidate_content=candidate,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_dynamic_relation_replay_binds_all_eligible_project_hashes(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": _PROJECT},
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    pending = store.prepare_poc_django_relation_settings_exhaustion_replay(
        exhausted, artifacts
    )
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    candidates = marker["settings_project_candidates"]
    assert [item["path"] for item in candidates] == [
        "project/config/settings.py",
        "zother/config/settings.py",
    ]
    assert all(
        item["ref"]["content_hash"] == hashlib.sha256(_PROJECT).hexdigest()
        for item in candidates
    )
    running = store.mark_running(
        exhausted.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="new-attempt",
    )
    assert relation_settings_replay_binding(running, artifacts) is not None


def test_dynamic_relation_replay_rejects_different_install_condition(
    tmp_path: Path,
) -> None:
    no_widget = _PROJECT.replace(
        b"'django.contrib.auth', 'widget'", b"'django.contrib.auth'"
    )
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": no_widget},
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_dynamic_relation_replay_does_not_ignore_root_settings_file(
    tmp_path: Path,
) -> None:
    conflicting = _PROJECT.replace(b"'false'", b"'true'")
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"settings.py": conflicting},
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


@pytest.mark.parametrize("ignored", (False, True))
def test_dynamic_relation_replay_rejects_nontracked_checkout_settings(
    tmp_path: Path,
    ignored: bool,
) -> None:
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    assert run.workspace_path is not None
    if ignored:
        (run.workspace_path / ".gitignore").write_text(
            "zother/config/settings.py\n", encoding="utf-8"
        )
    extra = run.workspace_path / "zother/config/settings.py"
    extra.parent.mkdir(parents=True)
    extra.write_bytes(_PROJECT.replace(b"'false'", b"'true'"))
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


@pytest.mark.parametrize(
    "mutation",
    (
        b"    candidates.insert(0, (Path('/workspace/zother/config/settings.py'), "
        b"{'WIDGET_TEAMS_ENABLED': True}))\n",
        b"    candidates[:0] = [(Path('/workspace/zother/config/settings.py'), "
        b"{'WIDGET_TEAMS_ENABLED': True})]\n",
    ),
)
def test_dynamic_relation_replay_rejects_candidate_list_mutation(
    tmp_path: Path,
    mutation: bytes,
) -> None:
    candidate = _DYNAMIC_CANDIDATE.replace(
        b"    candidates.sort(key=lambda item: str(item[0]))\n",
        mutation + b"    candidates.sort(key=lambda item: str(item[0]))\n",
    )
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        candidate_content=candidate,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_dynamic_relation_replay_ignores_tracked_project_outside_scan_root(
    tmp_path: Path,
) -> None:
    bounded = _DYNAMIC_CANDIDATE.replace(
        b"root = Path('/workspace')", b"root = Path('/workspace/project')"
    )
    conflicting = _PROJECT.replace(b"'false'", b"'true'")
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": conflicting},
        candidate_content=bounded,
    )
    pending = store.prepare_poc_django_relation_settings_exhaustion_replay(
        exhausted, artifacts
    )
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert [item["path"] for item in marker["settings_project_candidates"]] == [
        "project/config/settings.py"
    ]


def test_dynamic_relation_replay_rejects_rebound_scanned_path(
    tmp_path: Path,
) -> None:
    rebinding = _DYNAMIC_CANDIDATE.replace(
        b"root = Path('/workspace')",
        b"root = Path('/workspace/project')",
    ).replace(
        b"        values = literals(path)",
        b"        path = Path('/workspace/zother/config/settings.py')\n"
        b"        values = literals(path)",
    )
    conflicting = _PROJECT.replace(b"'false'", b"'true'")
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": conflicting},
        candidate_content=rebinding,
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_relation_source_binding_rejects_omitted_project_and_reads_old_marker(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_relation_attempt(
        tmp_path,
        extra_pinned={"zother/config/settings.py": _PROJECT},
        candidate_content=_DYNAMIC_CANDIDATE,
    )
    pending = store.prepare_poc_django_relation_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        exhausted.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="new-attempt",
    )
    original_ref = running.recovery_decision_refs[-1]
    marker = json.loads(artifacts.read(original_ref))

    def rebound(altered: dict[str, object]):  # type: ignore[no-untyped-def]
        changed_ref = artifacts.put_json(altered)
        refs = tuple(
            changed_ref if ref == original_ref else ref for ref in running.input_refs
        )
        return running.model_copy(
            update={
                "recovery_decision_refs": (
                    *running.recovery_decision_refs[:-1],
                    changed_ref,
                ),
                "input_refs": refs,
                "input_hash": input_reference_hash(refs),
            }
        )

    shortened = {
        **marker,
        "settings_project_candidates": marker["settings_project_candidates"][:1],
    }
    with pytest.raises(ValueError, match="POC_DJANGO_RELATION_SETTINGS_REPLAY_UNBOUND"):
        relation_settings_replay_binding(rebound(shortened), artifacts)

    legacy = {**marker, "recovery_revision": 1}
    legacy.pop("settings_project_candidates")
    legacy.pop("settings_project_selection")
    legacy.pop("settings_tracked_manifest_ref")
    legacy.pop("settings_reachable_sources")
    assert relation_settings_replay_binding(rebound(legacy), artifacts) is not None


def test_relation_settings_replay_is_one_shot_and_source_bound(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_relation_attempt(tmp_path)
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_content = artifacts.read(old_candidate.output_refs[1])
    old_stderr = artifacts.read(exhausted.output_refs[2])

    pending = store.prepare_poc_django_relation_settings_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert all(ref in pending.input_refs for ref in old_candidate.output_refs)
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert artifacts.read(old_candidate.output_refs[1]) == old_content
    assert artifacts.read(exhausted.output_refs[2]) == old_stderr
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["relation_settings_replay"] is True
    assert marker["settings_flag"] == "WIDGET_TEAMS_ENABLED"
    assert marker["settings_source_paths"] == list(_PINNED)
    with pytest.raises(ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )

    running = store.mark_running(
        identity, pending.stage, pending.input_refs, attempt_id="attempt-4"
    )
    with pytest.raises(
        Exception, match="POC_DJANGO_RELATION_SETTINGS_REPLAY_UNSUPPORTED"
    ):
        stages._reject_relation_settings_replay_content(running, artifacts, _CANDIDATE)
    repaired = _CANDIDATE.replace(
        b"    settings.configure(**options)",
        b"    options['WIDGET_TEAMS_ENABLED'] = False\n"
        b"    settings.configure(**options)",
    )
    stages._reject_relation_settings_replay_content(running, artifacts, repaired)


def test_relation_settings_replay_rejects_stale_or_unpinned_evidence(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_relation_attempt(tmp_path)
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_STALE"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted.model_copy(update={"attempt_id": "wrong"}), artifacts
        )
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    assert run.workspace_path is not None
    (run.workspace_path / "src/widget/models.py").write_text(
        "class Article: pass\n", encoding="utf-8"
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_RELATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_relation_settings_exhaustion_replay(
            exhausted, artifacts
        )


def test_application_requires_explicit_relation_settings_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_relation_attempt(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    asyncio.run(application.resume(identity.analysis_id))
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_relation_settings_exhaustion_hypothesis=(
                identity.hypothesis_id
            ),
        )
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_REPAIR_CONFLICT"):
        asyncio.run(
            application.resume(
                identity.analysis_id,
                repair_poc_django_relation_settings_exhaustion_hypothesis=(
                    identity.hypothesis_id
                ),
                repair_poc_django_schema_exhaustion_hypothesis=(identity.hypothesis_id),
            )
        )
