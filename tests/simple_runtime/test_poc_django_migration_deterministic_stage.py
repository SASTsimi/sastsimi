"""Pinned migration-setting repairs preserve the accepted PoC without LLM drift."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sastsimi.simple_runtime.stages as stage_module
from sastsimi.simple_runtime.django_migration_graph_omission import (
    django_migration_settings_replay_forbidden,
)
from sastsimi.simple_runtime.models import SimpleStage
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
from sastsimi.simple_runtime.stages import PoCCandidateStage
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _blocked_migration_candidate_attempt,
    _exhausted_migration_attempt,
)
from tests.unit.simple_runtime.test_django_migration_graph_omission import CANDIDATE


class _NoLLM:
    async def call(self, **_kwargs: object) -> None:
        raise AssertionError("a source-proven one-line repair must not call an LLM")


@pytest.mark.asyncio
async def test_pinned_migration_repair_changes_only_configuration_line(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-4"
    )
    result = await PoCCandidateStage(
        client=_NoLLM(),  # type: ignore[arg-type]
        artifacts=artifacts,
    )(running, {})
    assert len(result.output_refs) >= 2
    record = json.loads(artifacts.read(result.output_refs[0]))
    content = artifacts.read(result.output_refs[1])
    expected_line = b"    settings_values['HELPDESK_TEAMS_MODE_ENABLED'] = False\n"
    assert content.replace(expected_line, b"") == CANDIDATE
    assert (
        django_migration_settings_replay_forbidden(
            content, "HELPDESK_TEAMS_MODE_ENABLED"
        )
        is False
    )
    assert record["kind"] == "simple_poc_candidate"
    assert record["generation_mode"] == "pinned_migration_setting_patch_v1"
    assert record["attempt_id"] == running.attempt_id
    assert result.activity_events[0].stage == SimpleStage.POC_CANDIDATE_DONE.value


@pytest.mark.asyncio
async def test_candidate_only_replay_uses_original_accepted_poc_without_llm(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    result = await PoCCandidateStage(
        client=_NoLLM(),  # type: ignore[arg-type]
        artifacts=artifacts,
    )(running, {})
    content = artifacts.read(result.output_refs[1])
    assert (
        content.replace(
            b"    settings_values['HELPDESK_TEAMS_MODE_ENABLED'] = False\n", b""
        )
        == CANDIDATE
    )
    record = json.loads(artifacts.read(result.output_refs[0]))
    assert record["attempt_id"] == running.attempt_id
    assert record["generation_mode"] == "pinned_migration_setting_patch_v1"


@pytest.mark.asyncio
async def test_deterministic_replay_still_rejects_invalid_pro_con_anchor(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    # This synthetic fixture has an incomplete Pro/Con proposal. Production
    # replay must fail that existing anchor check before patching any PoC.
    pro_con = store.require(running.identity, SimpleStage.PRO_CON_DONE)
    with pytest.raises(StageFailed, match="Exact hypothesis"):
        await PoCCandidateStage(
            client=_NoLLM(),  # type: ignore[arg-type]
            artifacts=artifacts,
        )(running, {SimpleStage.PRO_CON_DONE: pro_con})


@pytest.mark.asyncio
async def test_one_shot_candidate_replay_does_not_fall_back_to_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    monkeypatch.setattr(
        stage_module,
        "insert_pinned_django_migration_false_override",
        lambda _content, _flag: None,
    )
    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(
            client=_NoLLM(),  # type: ignore[arg-type]
            artifacts=artifacts,
        )(running, {})
    assert error.value.failure.code == "POC_DJANGO_MIGRATION_PATCH_UNSUPPORTED"
    assert error.value.failure.retryable is False
