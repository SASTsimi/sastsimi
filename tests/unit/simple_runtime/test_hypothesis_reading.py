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
        "def guard(path):\n    for _ in range(8):\n        path = unquote(path)\n"
        + "".join(f"value_{index} = {index}\n" for index in range(40)),
        encoding="utf-8",
    )
    return workspace


def _proposal(line: int, statement: str = "decode cap bypass") -> dict[str, object]:
    """A proposal in the design's form, at one real line of app/proxy.py."""

    return {
        "statement": statement,
        "vulnerability_type_candidates": ["PATH_TRAVERSAL"],
        "target_locations": [
            {"file_path": "app/proxy.py", "start_line": line, "end_line": line}
        ],
        "suspected_path": [
            {
                "file_path": "app/proxy.py",
                "start_line": line,
                "end_line": line,
                "role": "sink",
            }
        ],
        "observed_facts": ["the loop stops at eight and proceeds"],
        "restrictions": [],
        "assumptions": ["the upstream decodes once more"],
        "falsification_questions": ["Does a nine-times-encoded path reach it?"],
        "validation_checks": ["Send a path encoded nine times."],
    }


class _ReadingAgent:
    """Asks for one file, then proposes using what it read."""

    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: object) -> SimpleLLMCallResult:
        prompt = kwargs.get("prompt")
        text = prompt if isinstance(prompt, bytes) else b""
        self.prompts.append(text)
        has_read = b"## What you have read so far" in text
        return SimpleLLMCallResult(
            value={
                "hypotheses": [_proposal(2)] if has_read else [],
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
async def test_the_code_is_read_without_anyone_choosing_it(
    tmp_path: Path, repository: Path
) -> None:
    """The first prompt already carries the source; nothing had to be asked for.

    An agent that chose files by name never opened the router whose sanitiser
    held the target defect.
    """

    _seeds, agent = await _propose(tmp_path, repository, _ReadingAgent())

    opening = agent.prompts[0]
    assert b"for _ in range(8):" in opening
    assert b"## Repository map" in opening
    # No pre-digested map of what someone decided was interesting.
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
            done = b"## What you have read so far" in text
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


class _Prolific(_ReadingAgent):
    """Proposes many distinct hypotheses and two copies of one."""

    async def call(self, **kwargs: object) -> SimpleLLMCallResult:
        prompt = kwargs.get("prompt")
        text = prompt if isinstance(prompt, bytes) else b""
        self.prompts.append(text)
        if b"reviewing one new proposal" in text:
            import re as _re

            target = _re.search(rb"hypothesis-[0-9a-f]{32}", text)
            return SimpleLLMCallResult(
                value={
                    "decision": "DUPLICATE",
                    "duplicate_of": target.group(0).decode() if target else None,
                    "rationale": "same loop",
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )
        hypotheses = [_proposal(index + 2, f"defect {index}") for index in range(20)]
        # The same defect again, from another batch's point of view.
        hypotheses.append(_proposal(2, "defect 0, seen again"))
        return SimpleLLMCallResult(
            value={
                "hypotheses": hypotheses,
                "requested_paths": [],
                "requested_ast_paths": [],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_as_many_hypotheses_as_the_code_gives_are_kept(
    tmp_path: Path, repository: Path
) -> None:
    """Twenty distinct defects are twenty hypotheses; twelve was an old cap."""

    seeds, _agent = await _propose(tmp_path, repository, _Prolific())

    assert len(seeds) == 20


@pytest.mark.asyncio
async def test_a_duplicate_review_that_fails_keeps_every_proposal(
    tmp_path: Path, repository: Path
) -> None:
    """A dropped proposal costs the defect; a duplicate costs one verification."""

    class _BrokenReview(_Prolific):
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs.get("prompt")
            if isinstance(prompt, bytes) and b"reviewing one new proposal" in prompt:
                from sastsimi.simple_runtime.models import StageFailure

                self.prompts.append(prompt)
                return StageFailure(  # type: ignore[return-value]
                    code="FAILED", retryable=True, safe_message="down"
                )
            return await super().call(**kwargs)

    seeds, _agent = await _propose(tmp_path, repository, _BrokenReview())

    assert len(seeds) == 21
