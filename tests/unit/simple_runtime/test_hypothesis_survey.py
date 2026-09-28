from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _answer(value: dict[str, Any]) -> SimpleLLMCallResult:
    return SimpleLLMCallResult(
        value=value, prompt_digest="a" * 64, output_digest="b" * 64
    )


def _proposal(line: int) -> dict[str, object]:
    return {
        "title": "SQL injection",
        "vulnerability_type": "SQLI",
        "summary": "untrusted query",
        "code_locations": [f"app.py:{line}"],
        "source": "user",
        "sink": "db.execute",
        "rationale": "no guard",
    }


class _SurveyClient:
    def __init__(self, *, fail_second: bool = False) -> None:
        self.fail_second = fail_second
        self.openings = 0
        self.batches: list[tuple[str, ...]] = []

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        del output_schema, timeout_ms
        if agent_name == "hypothesis_survey":
            self.openings += 1
            return _answer(
                {
                    "points": [
                        {
                            "key": f"P{index}",
                            "summary": f"point {index}",
                            "requested_sources": [],
                        }
                        for index in range(1, 10)
                    ]
                }
            )
        assert agent_name == "hypothesis_batch"
        marker = b"<POINTS>"
        points = json.loads(prompt.split(marker)[1].split(b"</POINTS>")[0])
        keys = tuple(item["key"] for item in points)
        self.batches.append(keys)
        if self.fail_second and len(self.batches) == 2:
            return StageFailure(code="RATE_LIMIT", retryable=True, safe_message="retry")
        return _answer(
            {
                "decisions": [
                    {"key": key, "status": "PROPOSED", "proposal": _proposal(2)}
                    if key == "P1"
                    else {"key": key, "status": "NOT_PROPOSED", "proposal": None}
                    for key in keys
                ]
            }
        )


def _setup(
    tmp_path: Path,
) -> tuple[CheckpointIdentity, StaticBootstrapResult, SimpleCheckpointStore]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "def route(user):\n    return db.execute(user)\n", encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="survey-analysis",
        workspace_id="survey-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": ["app.py"]}
    )
    static = StaticBootstrapResult(
        repository_profile_ref=artifacts.put_json(
            {"kind": "simple_repository_profile"}
        ),
        static_bundle_ref=artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            }
        ),
        workspace_path=workspace,
    )
    return identity, static, SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")


@pytest.mark.asyncio
async def test_survey_batches_eight_then_one_and_deduplicates(tmp_path: Path) -> None:
    identity, static, store = _setup(tmp_path)
    client = _SurveyClient()
    seeds = await DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda *_: client,
        feed="facts_survey",
        store=store,
    ).propose(identity, static)

    assert not isinstance(seeds, StageFailure)
    assert len(seeds) == 1
    assert [len(batch) for batch in client.batches] == [8, 1]
    progress = store.survey_progress(
        identity.analysis_id, static.static_bundle_ref.content_hash
    )
    assert len(progress) == 10
    assert "__survey__" in progress


@pytest.mark.asyncio
async def test_failed_second_batch_resumes_without_repeating_first(
    tmp_path: Path,
) -> None:
    identity, static, store = _setup(tmp_path)
    first = _SurveyClient(fail_second=True)
    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda *_: first,
        feed="facts_survey",
        store=store,
    )
    failed = await bootstrap.propose(identity, static)
    assert isinstance(failed, StageFailure)
    assert (
        len(
            store.survey_progress(
                identity.analysis_id, static.static_bundle_ref.content_hash
            )
        )
        == 9
    )

    reopened = SimpleCheckpointStore(store.database_path)
    second = _SurveyClient()
    seeds = await DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda *_: second,
        feed="facts_survey",
        store=reopened,
    ).propose(identity, static)

    assert not isinstance(seeds, StageFailure)
    assert len(seeds) == 1
    assert second.openings == 0
    assert second.batches == [("P9",)]


def test_conflicting_survey_decision_fails_closed(tmp_path: Path) -> None:
    identity, static, store = _setup(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first = artifacts.put_json({"key": "P1", "status": "NOT_PROPOSED"})
    second = artifacts.put_json({"key": "P1", "status": "PROPOSED"})
    store.save_survey_progress(
        identity.analysis_id, static.static_bundle_ref.content_hash, "P1", first
    )
    with pytest.raises(ValueError, match="SURVEY_PROGRESS_CONFLICT"):
        store.save_survey_progress(
            identity.analysis_id, static.static_bundle_ref.content_hash, "P1", second
        )


@pytest.mark.asyncio
async def test_reserved_progress_key_from_agent_is_rejected(tmp_path: Path) -> None:
    identity, static, store = _setup(tmp_path)

    class ReservedKeyClient(_SurveyClient):
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult | StageFailure:
            if kwargs.get("agent_name") == "hypothesis_survey":
                return _answer(
                    {
                        "points": [
                            {
                                "key": "__survey__",
                                "summary": "bad",
                                "requested_sources": [],
                            }
                        ]
                    }
                )
            return await super().call(**kwargs)

    result = await DirectHypothesisBootstrap(
        data_dir=tmp_path / "data",
        client_factory=lambda *_: ReservedKeyClient(),
        feed="facts_survey",
        store=store,
    ).propose(identity, static)

    assert isinstance(result, StageFailure)
    assert result.code == "HYPOTHESIS_SURVEY_INVALID"
