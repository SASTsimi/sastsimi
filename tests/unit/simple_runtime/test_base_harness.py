from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sastsimi.simple_runtime.base_harness import BaseHarness


class _Docker:
    def __init__(self, outcomes: list[tuple[int, str, str]]) -> None:
        self.outcomes = outcomes
        self.runs = 0

    async def create_container(
        self, image_digest: str, labels: dict[str, str]
    ) -> str:
        return "a" * 64

    async def materialize_poc(
        self, container_id: str, content: bytes, digest: str
    ) -> str:
        return "/tmp/sastsimi-poc-candidate"

    async def execute(
        self, container_id: str, argv: Any, timeout_ms: int, **kw: Any
    ) -> Any:
        code, out, err = self.outcomes[min(self.runs, len(self.outcomes) - 1)]
        self.runs += 1
        return SimpleNamespace(
            exit_code=code, stdout=out.encode(), stderr=err.encode(), timed_out=False
        )

    async def remove(self, container_ids: tuple[str, ...]) -> None:
        return None


class _Client:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, *, prompt: bytes, output_schema: Any, timeout_ms: int) -> Any:
        self.prompts.append(prompt)
        return SimpleNamespace(value={"content": "#!/bin/sh\necho HARNESS_OK\n"})


def _harness(tmp_path: Path, docker: _Docker, client: _Client) -> BaseHarness:
    (tmp_path / "ws" / "tests").mkdir(parents=True)
    (tmp_path / "ws" / "tests" / "test.env").write_text("DB_URI=x\n")
    return BaseHarness(
        data_dir=tmp_path / "data",
        workspace=tmp_path / "ws",
        docker=docker,  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        analysis_id="a",
        labels={},
    )


def test_a_proved_base_is_returned_and_reused(tmp_path: Path) -> None:
    docker, client = _Docker([(0, "HARNESS_OK 200", "")]), _Client()
    harness = _harness(tmp_path, docker, client)

    first = asyncio.run(harness.ensure("sha256:abc"))
    second = asyncio.run(harness.ensure("sha256:abc"))

    assert first and "HARNESS_OK" in first
    assert second == first
    assert len(client.prompts) == 1
    assert b"tests/test.env" in client.prompts[0]


def test_a_failing_base_is_retried_with_its_output_then_given_up(
    tmp_path: Path,
) -> None:
    docker, client = _Docker([(2, "", "KeyError: 'EMAIL_DOMAIN'")]), _Client()
    harness = _harness(tmp_path, docker, client)

    assert asyncio.run(harness.ensure("sha256:abc")) is None
    assert len(client.prompts) == 3
    assert b"KeyError: 'EMAIL_DOMAIN'" in client.prompts[1]
    assert asyncio.run(harness.ensure("sha256:abc")) is None
    assert len(client.prompts) == 3
