"""Bounded Django PoC schema preflight before container execution."""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    SimpleRecoveryCoordinator,
)
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import PoCCandidateStage


def _shell_python(body: str) -> str:
    return "#!/bin/sh\npython3 - <<'PY'\n" + body + "\nPY\n"


_PARTIAL_SCHEMA = _shell_python(
    "import django\n"
    "from django.db import connection\n"
    "django.setup()\n"
    "with connection.schema_editor() as editor:\n"
    "    for model in (Queue, Ticket, FollowUp):\n"
    "        editor.create_model(model)"
)
_OUTER_PARTIAL_SCHEMA = _shell_python(
    "import django\n"
    "from django.db import connection\n"
    "django.setup()\n"
    "for model in (Queue, Ticket, FollowUp):\n"
    "    with connection.schema_editor() as editor:\n"
    "        editor.create_model(model)"
)
_SEEDED_PARTIAL_SCHEMA = _shell_python(
    "import django\n"
    "from django.db import connection\n"
    "django.setup()\n"
    "models = []\n"
    "def include_model(model):\n"
    "    models.append(model)\n"
    "for model in (Queue, Ticket, FollowUp):\n"
    "    include_model(model)\n"
    "with connection.schema_editor() as editor:\n"
    "    for model in models:\n"
    "        editor.create_model(model)"
)
_WRAPPED_SEEDED_PARTIAL_SCHEMA = _shell_python(
    "try:\n"
    + textwrap.indent(
        _SEEDED_PARTIAL_SCHEMA.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0],
        "    ",
    )
    + "\nexcept RuntimeError:\n    pass"
)
_MIGRATION_SCHEMA = _shell_python(
    "import django\n"
    "from django.core.management import call_command\n"
    "django.setup()\n"
    "call_command('migrate', run_syncdb=True)"
)
_ALL_MODELS_SCHEMA = _shell_python(
    "import django\n"
    "from django.apps import apps\n"
    "from django.db import connection\n"
    "django.setup()\n"
    "with connection.schema_editor() as editor:\n"
    "    for model in apps.get_models():\n"
    "        editor.create_model(model)"
)


class _CandidateClient:
    def __init__(self, *contents: str) -> None:
        self.contents = contents
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        index = min(len(self.prompts) - 1, len(self.contents) - 1)
        return SimpleLLMCallResult(
            value={"content": self.contents[index]},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _NoRecoveryLLM:
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        raise AssertionError("schema preflight rejection must be categorized by rule")


async def _run_candidate(tmp_path: Path, client: _CandidateClient) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-schema",
        workspace_id="workspace-schema",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-schema",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-schema",
    )
    await PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )(checkpoint, {})


def test_explicit_django_schema_subset_is_repaired_before_candidate_commit(
    tmp_path: Path,
) -> None:
    client = _CandidateClient(_PARTIAL_SCHEMA, _MIGRATION_SCHEMA)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2
    assert b"POC_DJANGO_SCHEMA_SUBSET_UNVERIFIED" in client.prompts[1]
    assert b"migrate" in client.prompts[1]
    assert b"run_syncdb" in client.prompts[1]


def test_outer_model_loop_is_repaired_before_candidate_commit(tmp_path: Path) -> None:
    client = _CandidateClient(_OUTER_PARTIAL_SCHEMA, _MIGRATION_SCHEMA)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2


def test_explicitly_seeded_model_list_is_repaired_before_candidate_commit(
    tmp_path: Path,
) -> None:
    client = _CandidateClient(_SEEDED_PARTIAL_SCHEMA, _MIGRATION_SCHEMA)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2


def test_explicit_model_list_in_try_block_is_repaired_before_candidate_commit(
    tmp_path: Path,
) -> None:
    client = _CandidateClient(_WRAPPED_SEEDED_PARTIAL_SCHEMA, _MIGRATION_SCHEMA)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2


@pytest.mark.parametrize(
    "other_schema_setup",
    [
        "call_command('migrate', run_syncdb=True)",
        "models = apps.get_models()",
        "if False:\n    call_command('migrate', run_syncdb=True)",
        (
            "try:\n    call_command('migrate', run_syncdb=True)\n"
            "except Exception:\n    pass"
        ),
    ],
    ids=(
        "migration-before-subset",
        "all-models-call-before-subset",
        "unreachable-migration",
        "caught-migration-failure",
    ),
)
def test_other_schema_setup_does_not_hide_explicit_model_subset(
    tmp_path: Path, other_schema_setup: str
) -> None:
    mixed_script = _PARTIAL_SCHEMA.replace(
        "with connection.schema_editor() as editor:",
        other_schema_setup + "\nwith connection.schema_editor() as editor:",
    )
    client = _CandidateClient(mixed_script, _MIGRATION_SCHEMA)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2
    assert b"POC_DJANGO_SCHEMA_SUBSET_UNVERIFIED" in client.prompts[1]


def test_persistently_partial_django_schema_is_blocked_not_confirmed(
    tmp_path: Path,
) -> None:
    client = _CandidateClient(_PARTIAL_SCHEMA)

    with pytest.raises(StageBlocked) as blocked:
        asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 2
    assert blocked.value.failure.code == "POC_DJANGO_SCHEMA_SUBSET_UNVERIFIED"
    assert blocked.value.failure.retryable is True


@pytest.mark.parametrize(
    "stage",
    [SimpleStage.POC_CANDIDATE_DONE, SimpleStage.POC_EXECUTION_DONE],
)
def test_django_schema_preflight_recovery_is_generated_input(
    tmp_path: Path, stage: SimpleStage
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-schema",
        workspace_id="workspace-schema",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-schema",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=stage,
        status=StageStatus.BLOCKED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-schema",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)

    result = asyncio.run(
        SimpleRecoveryCoordinator(
            client=_NoRecoveryLLM(),
            artifacts=artifacts,
        ).decide(
            checkpoint,
            StageFailure(
                code="POC_DJANGO_SCHEMA_SUBSET_UNVERIFIED",
                retryable=True,
                safe_message="Django schema setup is unverified",
            ),
        )
    )

    assert result.decision.category is RecoveryCategory.GENERATED_INPUT
    assert result.decision.action is RecoveryAction.REGENERATE_INPUT


@pytest.mark.parametrize(
    "content",
    [
        _MIGRATION_SCHEMA,
        _ALL_MODELS_SCHEMA,
        _shell_python("print('ordinary Python PoC')"),
        _shell_python(
            "with connection.schema_editor() as editor:\n"
            "    editor.create_model(Ticket)"
        ),
        (
            "#!/bin/sh\ncat <<'DATA'\n"
            + _PARTIAL_SCHEMA.split("#!/bin/sh\n", 1)[1]
            + "DATA\n"
        ),
        _shell_python(
            "import django\ndjango.setup()\n"
            "# with connection.schema_editor() as editor: editor.create_model(Ticket)\n"
            "print('ordinary fixture')"
        ),
        _shell_python(
            "import django\nfrom django.db import connection\ndjango.setup()\n"
            "models = discover_models()\n"
            "with connection.schema_editor() as editor:\n"
            "    for model in models:\n"
            "        editor.create_model(model)"
        ),
    ],
    ids=(
        "migration",
        "all-installed-models",
        "non-django",
        "no-django-signal",
        "nested-inert-heredoc",
        "comment-only",
        "opaque-model-discovery",
    ),
)
def test_schema_preflight_does_not_reject_other_pocs(
    tmp_path: Path, content: str
) -> None:
    client = _CandidateClient(content)

    asyncio.run(_run_candidate(tmp_path, client))

    assert len(client.prompts) == 1
