"""One explicit candidate replay for an invented Django app in a PoC."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import PoCCandidateStage, PoCExecutionStage
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_fixture_dependency_replay import (
    _exhausted_attempt_four,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_CANDIDATE = b"""#!/bin/sh
cd /workspace || exit 2
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python - <<'PY'
from django.conf import settings
print('Pinned follow-up view source matched', flush=True)
settings.configure(
    INSTALLED_APPS=['django.contrib.auth', 'invented_app', 'helpdesk'],
)
stage = 'import'
import django
django.setup()
from django.test import Client
response = Client().get('/target/')
PY
"""
_STDERR = b"""ModuleNotFoundError: invented_app
Traceback (most recent call last):
  at unresolved_frame:105
  at setup:24
  at populate:91
  at create:193
  at import_module:90
  at _gcd_import:1387
  at _find_and_load:1360
  at _find_and_load_unlocked:1324
"""
_STDOUT = b"Pinned follow-up view source matched\n"


class _CandidateClient:
    def __init__(self, content: bytes) -> None:
        self.content = content.decode("utf-8")

    async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
        return SimpleLLMCallResult(
            value={"content": self.content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _commit_checkout(
    tmp_path: Path,
    *,
    extra: str = "",
    reexport: bool = False,
    helper_source: str | None = None,
    helper_path: str = "helper.py",
) -> str:
    workspace = tmp_path / "data" / "workspaces" / "workspace-1"
    workspace.mkdir(parents=True)
    (workspace / "settings.py").write_text(
        "INSTALLED_APPS = ['django.contrib.auth', 'helpdesk']\n" + extra,
        encoding="utf-8",
    )
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "target"\nversion = "1"\ndependencies = ["django"]\n',
        encoding="utf-8",
    )
    if reexport:
        (workspace / "local_settings.py").write_text(
            "from .settings import *\n", encoding="utf-8"
        )
    if helper_source is not None:
        (workspace / helper_path).parent.mkdir(parents=True, exist_ok=True)
        (workspace / helper_path).write_text(helper_source, encoding="utf-8")
    for args in (
        ("init", "-q"),
        (
            "add",
            "settings.py",
            "pyproject.toml",
            *(("local_settings.py",) if reexport else ()),
            *((helper_path,) if helper_source is not None else ()),
        ),
        (
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "pinned source",
        ),
    ):
        subprocess.run(("git", *args), cwd=workspace, check=True, capture_output=True)
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _exhausted_app(tmp_path: Path, **changes: object):  # type: ignore[no-untyped-def]
    helper_source = changes.pop("helper_source", None)
    assert helper_source is None or isinstance(helper_source, str)
    commit = _commit_checkout(
        tmp_path,
        extra=str(changes.pop("source_extra", "")),
        reexport=bool(changes.pop("reexport_settings", False)),
        helper_source=helper_source,
        helper_path=str(changes.pop("helper_path", "helper.py")),
    )
    options: dict[str, object] = {
        "candidate_content": _CANDIDATE,
        "stdout": _STDOUT,
        "stderr": _STDERR,
        "seed_commit_id": commit,
        "failure_code": "POC_RUNTIME_IMPORT_FAILED",
    }
    recipe_patch = changes.pop("recipe_patch", {})
    assert isinstance(recipe_patch, dict)
    options.update(changes)
    store, artifacts, exhausted = _exhausted_attempt_four(
        tmp_path,
        candidate_content=cast(bytes, options["candidate_content"]),
        stdout=cast(bytes, options["stdout"]),
        stderr=cast(bytes, options["stderr"]),
        execution_patch=cast(dict[str, object] | None, options.get("execution_patch")),
        cleanup_status=cast(str, options.get("cleanup_status", "REMOVED")),
        seed_commit_id=cast(str, options["seed_commit_id"]),
        failure_code=cast(str, options["failure_code"]),
    )
    identity = exhausted.identity
    recipe = {
        "kind": "simple_environment_recipe",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "hypothesis_id": identity.hypothesis_id,
        "attempt_id": "attempt-1",
        "dockerfile_source": "GENERATED",
        "status": "BUILT",
        "degraded": False,
        "image_digest": exhausted.image_digest,
    }
    recipe.update(recipe_patch)
    recipe_ref = artifacts.put_json(recipe)
    for stage in (
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ):
        checkpoint = store.require(identity, stage)
        store.save_checkpoint(checkpoint.model_copy(update={"recipe_ref": recipe_ref}))
    return store, artifacts, store.require(identity, SimpleStage.POC_EXECUTION_DONE)


def test_candidate_app_replay_preserves_attempt_and_reseeds_only_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path)
    identity = exhausted.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 4
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert artifacts.read(candidate.output_refs[1]) == _CANDIDATE
    assert artifacts.read(exhausted.output_refs[2]) == _STDERR
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert rule["candidate_app_replay"] is True
    assert rule["original_error"]["code"] == "POC_RUNTIME_IMPORT_FAILED"
    assert "repository-supported" in rule["decision"]["guidance"]
    assert "pip install" not in rule["decision"]["guidance"]
    assert "invented_app" not in json.dumps(rule)
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(events_after) == len(events_before) + 1
    assert events_after[-1].kind is ActivityKind.DECISION_RECORDED
    assert events_after[-1].error_code == "POC_CANDIDATE_APP_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_CANDIDATE_APP_EXHAUSTION_"):
        store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)


def test_absent_optional_local_settings_does_not_block_pinned_app_proof(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(
        tmp_path,
        source_extra=(
            "try:\n    from .local_settings import *\nexcept ImportError:\n    pass\n"
        ),
    )

    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING


def test_optional_local_settings_ignores_same_name_elsewhere(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(
        tmp_path,
        source_extra=(
            "try:\n    from .local_settings import *\nexcept ImportError:\n    pass\n"
        ),
        helper_path="other/local_settings.py",
        helper_source="FLAG = True\n",
    )

    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING


def test_unrelated_usersettings_module_import_does_not_block_app_proof(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(
        tmp_path,
        helper_path="create_usersettings.py",
        helper_source="import settings\n",
    )

    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING


def test_literal_settings_reexport_does_not_block_pinned_app_proof(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path, reexport_settings=True)

    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING


@pytest.mark.parametrize(
    "change",
    [
        {"source_extra": "INSTALLED_APPS.append('invented_app')\n"},
        {"source_extra": "INSTALLED_APPS.append('invented' + '_app')\n"},
        {
            "source_extra": (
                "vars()['INSTALLED' + '_APPS'].append('invented' + '_app')\n"
            )
        },
        {
            "source_extra": (
                "apps = vars()['INSTALLED' + '_APPS']\n"
                "apps.append('invented' + '_app')\n"
            )
        },
        {"source_extra": "if enabled:\n    INSTALLED_APPS = ['helpdesk']\n"},
        {"source_extra": "INSTALLED_APPS = ['django.contrib.auth']\n"},
        {
            "source_extra": "from helper import mutate\nmutate()\n",
            "helper_source": (
                "import settings as target\n"
                "vars(target)['INSTALLED' + '_APPS'].append('invented' + '_app')\n"
            ),
        },
        {
            "source_extra": "from helper import mutate\nmutate()\n",
            "helper_path": "src/helper.py",
            "helper_source": (
                "import settings as target\n"
                "vars(target)['INSTALLED' + '_APPS'].append('invented' + '_app')\n"
            ),
        },
        {"source_extra": "import invented_app\n"},
        {"source_extra": "# dependency: invented-app\n"},
        {"candidate_content": _CANDIDATE.replace(b"'invented_app', ", b"'helpdesk', ")},
        {"candidate_content": _CANDIDATE.replace(b"'invented_app'", b"'secret_token'")},
        {"stdout": _STDOUT + b"REPRODUCED\n"},
        {"stderr": _STDERR + b"AssertionError: later\n"},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"candidate_ref": None}},
        {"cleanup_status": "UNKNOWN"},
        {"failure_code": "POC_EXECUTION_FAILED"},
        {"recipe_patch": {"analysis_id": "other-analysis"}},
        {"recipe_patch": {"workspace_id": "other-workspace"}},
        {"recipe_patch": {"commit_id": "f" * 40}},
        {"recipe_patch": {"hypothesis_id": "other-hypothesis"}},
        {"recipe_patch": {"attempt_id": ""}},
        {"recipe_patch": {"status": "FAILED"}},
        {"recipe_patch": {"degraded": True}},
        {"recipe_patch": {"image_digest": "sha256:" + "f" * 64}},
        {"recipe_patch": {"dockerfile_source": "UNKNOWN"}},
    ],
)
def test_candidate_app_replay_rejects_unproven_error_without_mutation(
    tmp_path: Path, change: dict[str, object]
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path, **change)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(ValueError, match="POC_CANDIDATE_APP_EXHAUSTION_"):
        store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


@pytest.mark.asyncio
async def test_candidate_app_replay_allows_clean_regenerated_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path)
    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    content = b"#!/bin/sh\nprintf 'fixture_value\\n'\n"

    result = await PoCCandidateStage(
        client=_CandidateClient(content),
        artifacts=artifacts,
    )(running, {})

    assert artifacts.read(result.output_refs[1]) == content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        b"#!/bin/sh\npython -m pip install invented-app\n",
        b"#!/bin/sh\npip install --target /tmp invented-app\n",
        (
            b"#!/bin/sh\npython - <<'PY'\n"
            b"import pip\npip.main(['install', 'invented-app'])\nPY\n"
        ),
    ],
)
async def test_candidate_app_replay_rejects_unsupported_app_install_before_save(
    tmp_path: Path, content: bytes
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path)
    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )

    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(
            client=_CandidateClient(content),
            artifacts=artifacts,
        )(running, {})

    assert error.value.failure.code == "POC_CANDIDATE_APP_REPLAY_UNSUPPORTED"
    assert store.require(running.identity, running.stage) == running


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "later_decision,unbound_marker",
    [(False, False), (True, False), (False, True)],
)
async def test_saved_candidate_app_replay_cannot_execute_unsupported_app(
    tmp_path: Path,
    later_decision: bool,
    unbound_marker: bool,
) -> None:
    store, artifacts, exhausted = _exhausted_app(tmp_path)
    pending = store.prepare_poc_candidate_app_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    content = b"#!/bin/sh\npython -m pip install invented-app\n"
    content_ref = artifacts.put_bytes(content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": running.attempt_id,
            "content_ref": content_ref.model_dump(mode="json"),
        }
    )
    candidate = store.complete(
        running,
        StageResult(output_refs=(candidate_ref, content_ref)),
    )
    if later_decision:
        unrelated_ref = artifacts.put_json({"kind": "simple_recovery_decision"})
        inputs = (*candidate.input_refs, unrelated_ref)
        candidate = candidate.model_copy(
            update={
                "input_refs": inputs,
                "input_hash": input_reference_hash(inputs),
                "recovery_decision_refs": (
                    *candidate.recovery_decision_refs,
                    unrelated_ref,
                ),
            }
        )
    if unbound_marker:
        marker_ref = candidate.recovery_decision_refs[-1]
        inputs = tuple(ref for ref in candidate.input_refs if ref != marker_ref)
        candidate = candidate.model_copy(
            update={"input_refs": inputs, "input_hash": input_reference_hash(inputs)}
        )
    execution = store.mark_running(
        running.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-5",
        inherit_from=candidate,
    )

    class NoContainer:
        async def acquire(self, *_args: object) -> str:
            raise AssertionError("Docker must not be reached")

    with pytest.raises(StageBlocked) as error:
        await PoCExecutionStage(
            client=_CandidateClient(content),
            artifacts=artifacts,
            docker=object(),  # type: ignore[arg-type]
            containers=NoContainer(),  # type: ignore[arg-type]
        )(execution, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert error.value.failure.code == "POC_CANDIDATE_APP_REPLAY_UNSUPPORTED"


@pytest.mark.asyncio
async def test_application_requires_explicit_candidate_app_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_app(tmp_path)
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
    await application.resume(identity.analysis_id)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted

    await application.resume(
        identity.analysis_id,
        repair_poc_candidate_app_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_cli_forwards_explicit_candidate_app_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_candidate_app_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_candidate_app_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_candidate_app_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_candidate_app_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-candidate-app-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()


def test_cli_reports_candidate_app_replay_integrity_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class InvalidReplay(_PublicApplication):
        def resume(self, analysis_id: str, **_kwargs: object) -> dict[str, object]:
            del analysis_id
            raise ValueError("POC_CANDIDATE_APP_EXHAUSTION_EVIDENCE_INVALID")

    code = main(
        [
            "resume",
            "A-001",
            "--repair-poc-candidate-app-exhaustion",
            "hypothesis-1",
            "--format",
            "json",
        ],
        public_application=InvalidReplay(),
        user_config_store=_config(tmp_path),
    )

    assert code == int(ExitCode.INTEGRITY_ERROR)
    assert "POC_CANDIDATE_APP_EXHAUSTION_EVIDENCE_INVALID" in capsys.readouterr().err


def test_cli_does_not_claim_unrelated_fixture_dependency_error(
    tmp_path: Path,
) -> None:
    class InvalidReplay(_PublicApplication):
        def resume(self, analysis_id: str, **_kwargs: object) -> dict[str, object]:
            del analysis_id
            raise ValueError("UNRELATED_FAILURE")

    code = main(
        [
            "resume",
            "A-001",
            "--repair-poc-fixture-dependency-exhaustion",
            "hypothesis-1",
            "--format",
            "json",
        ],
        public_application=InvalidReplay(),
        user_config_store=_config(tmp_path),
    )

    assert code == int(ExitCode.INTERNAL_ERROR)
