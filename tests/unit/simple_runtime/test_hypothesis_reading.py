"""Which files a run ever looks at is decided when hypotheses are proposed.

A defect behind a guard that is present but wrong produces no static finding at
all, so an agent given only static findings can never propose it.  It is given
the checkout's file list instead, and may read before it decides.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import DirectHypothesisBootstrap
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.provider import SimpleLLMCallResult

_COMMIT = "a" * 40


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id=_COMMIT,
        hypothesis_id=None,
    )


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    workspace = tmp_path / "repo"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "proxy.py").write_text(
        "def guard(path):\n    for _ in range(8):\n        path = unquote(path)\n",
        encoding="utf-8",
    )
    return workspace


class _ReadingAgent:
    """Asks for one file, then proposes using what it read."""

    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: object) -> SimpleLLMCallResult:
        prompt = kwargs.get("prompt")
        text = prompt if isinstance(prompt, bytes) else b""
        self.prompts.append(text)
        has_read = b"simple_exploration_history" in text
        return SimpleLLMCallResult(
            value={
                "hypotheses": (
                    [
                        {
                            "title": "decode cap bypass",
                            "vulnerability_type": "PATH_TRAVERSAL",
                            "summary": "the loop stops at eight and proceeds",
                            "code_locations": ["app/proxy.py:2"],
                            "source": "path",
                            "sink": "upstream",
                            "rationale": "read the file",
                        }
                    ]
                    if has_read
                    else []
                ),
                "requested_paths": [] if has_read else ["app/proxy.py"],
                "requested_ast_paths": [],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


async def _propose(
    tmp_path: Path, repository: Path, agent: _ReadingAgent
) -> tuple[Any, _ReadingAgent]:
    data_dir = tmp_path / "data"
    identity = _identity()
    artifacts = SimpleArtifactRepository(data_dir, identity)
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "source_files": ["app/proxy.py"],
            "codeql_findings": [],
            "opengrep_findings": [],
            "tool_result_refs": [],
        }
    )
    bootstrap = DirectHypothesisBootstrap(
        data_dir=data_dir,
        client_factory=cast(Any, lambda *a, **k: agent),
    )
    seeds = await bootstrap.propose(
        identity,
        StaticBootstrapResult(
            repository_profile_ref=bundle_ref,
            static_bundle_ref=bundle_ref,
            workspace_path=repository,
        ),
    )
    return seeds, agent


@pytest.mark.asyncio
async def test_the_agent_may_read_before_it_proposes(
    tmp_path: Path, repository: Path
) -> None:
    seeds, agent = await _propose(tmp_path, repository, _ReadingAgent())

    assert len(agent.prompts) == 2
    assert len(seeds) == 1
    # The second prompt carried the file it asked for, contents and all.
    assert b"for _ in range(8)" in agent.prompts[1]


@pytest.mark.asyncio
async def test_the_file_list_is_offered_without_a_selection(
    tmp_path: Path, repository: Path
) -> None:
    _seeds, agent = await _propose(tmp_path, repository, _ReadingAgent())

    opening = agent.prompts[0]
    assert b"source_files" in opening
    assert b"app/proxy.py" in opening
    # No pre-digested map of what someone decided was interesting.
    assert b"ast_index" not in opening
    assert b"notable_calls" not in opening


@pytest.mark.asyncio
async def test_an_agent_that_reads_nothing_is_called_once(
    tmp_path: Path, repository: Path
) -> None:
    class _Decisive(_ReadingAgent):
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs.get("prompt")
            self.prompts.append(prompt if isinstance(prompt, bytes) else b"")
            return SimpleLLMCallResult(
                value={
                    "hypotheses": [],
                    "requested_paths": [],
                    "requested_ast_paths": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    _seeds, agent = await _propose(tmp_path, repository, _Decisive())

    assert len(agent.prompts) == 1


@pytest.mark.asyncio
async def test_a_path_outside_the_checkout_is_refused_not_read(
    tmp_path: Path, repository: Path
) -> None:
    class _Escaping(_ReadingAgent):
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs.get("prompt")
            text = prompt if isinstance(prompt, bytes) else b""
            self.prompts.append(text)
            done = b"simple_exploration_history" in text
            return SimpleLLMCallResult(
                value={
                    "hypotheses": [],
                    "requested_paths": [] if done else ["../../etc/passwd"],
                    "requested_ast_paths": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    _seeds, agent = await _propose(tmp_path, repository, _Escaping())

    history = agent.prompts[1]
    assert b"PATH_OUTSIDE_REPOSITORY" in history
    assert b"root:" not in history


def test_the_listing_offers_the_checkout_rather_than_a_selection() -> None:
    """The whole source list, chosen by extension and nothing else.

    A list narrowed by what someone thought was interesting is the judgement a
    static rule makes, and it fails the same way.
    """

    from sastsimi.simple_runtime.bootstrap_stages import _source_listing

    listing = _source_listing(
        (
            "app/z_last.py",
            "app/a_first.ts",
            "docs/readme.md",
            "app/vendor/huge.py",
            "assets/logo.png",
            "app/types.PYI",
        )
    )

    assert listing == [
        "app/a_first.ts",
        "app/types.PYI",
        "app/vendor/huge.py",
        "app/z_last.py",
    ]


def test_a_repository_with_no_source_lists_nothing_rather_than_guessing() -> None:
    from sastsimi.simple_runtime.bootstrap_stages import _source_listing

    assert _source_listing(("README.md", "LICENSE")) == []


@pytest.mark.asyncio
async def test_each_proposal_records_which_files_were_read(
    tmp_path: Path, repository: Path
) -> None:
    """A run that misses a defect must be able to say whether the file was read.

    One run proposed four hypotheses, none about the target file, and nothing
    recorded whether the agent had opened that file and dismissed it or never
    opened it at all.
    """

    await _propose(tmp_path, repository, _ReadingAgent())

    data = tmp_path / "data"
    proposals = [
        json.loads(path.read_bytes())
        for path in data.rglob("*")
        if path.is_file() and b"simple_hypothesis_proposal" in path.read_bytes()
    ]
    assert proposals
    reading = proposals[0]["reading"]
    assert reading == [
        {
            "round": 1,
            "requested": ["app/proxy.py"],
            "served": ["app/proxy.py"],
            "refused": [],
        }
    ]
