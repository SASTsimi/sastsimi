"""Every agent request shares one ceiling, in the order it arrived."""

from __future__ import annotations

import asyncio

import pytest

from sastsimi.simple_runtime.call_queue import CallQueue


@pytest.mark.asyncio
async def test_the_ceiling_is_shared_by_every_caller() -> None:
    # Six hypotheses each holding a private ceiling of two is what this
    # replaces: the total, not the per-caller count, is what the host pays.
    queue = CallQueue(max_concurrent=2)
    live = 0
    peak = 0

    async def call() -> None:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        live -= 1

    await asyncio.wait_for(
        asyncio.gather(*(queue.submit(call) for _ in range(12))), timeout=2
    )

    assert peak == 2
    assert queue.peak_running == 2


@pytest.mark.asyncio
async def test_requests_start_in_the_order_they_arrived() -> None:
    queue = CallQueue(max_concurrent=1)
    order: list[int] = []

    async def call(index: int) -> None:
        order.append(index)
        await asyncio.sleep(0)

    tasks = []
    for index in range(8):
        tasks.append(asyncio.create_task(queue.submit(lambda i=index: call(i))))
        # Let each submission register before the next arrives.
        await asyncio.sleep(0)
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=2)

    assert order == list(range(8))


@pytest.mark.asyncio
async def test_a_failing_request_frees_its_slot() -> None:
    queue = CallQueue(max_concurrent=1)

    async def boom() -> None:
        raise RuntimeError("no")

    with pytest.raises(RuntimeError):
        await queue.submit(boom)

    async def ok() -> str:
        return "ok"

    assert await asyncio.wait_for(queue.submit(ok), timeout=1) == "ok"


@pytest.mark.asyncio
async def test_a_cancelled_request_does_not_block_the_queue() -> None:
    queue = CallQueue(max_concurrent=1)
    release = asyncio.Event()

    async def held() -> None:
        await release.wait()

    first = asyncio.create_task(queue.submit(held))
    await asyncio.sleep(0)
    second = asyncio.create_task(queue.submit(held))
    await asyncio.sleep(0)
    third = asyncio.create_task(queue.submit(held))
    await asyncio.sleep(0)

    second.cancel()
    await asyncio.sleep(0)
    release.set()
    await asyncio.wait_for(asyncio.gather(first, third), timeout=1)
    assert second.cancelled()


@pytest.mark.asyncio
async def test_two_clients_sharing_a_queue_share_the_ceiling(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A client is built per hypothesis, so a per-client ceiling multiplies."""

    from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
    from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding

    profile = SimpleExecutionProfile(
        provider_profile_ref="local-claude",
        provider="claude",
        model="claude-sonnet-5",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=500_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        max_parallel_calls=4,
        tools={
            "docker": SimpleToolBinding(
                executable_path=tmp_path / "docker",
                version="28.2.2",
                executable_sha256="a" * 64,
            )
        },
    )
    factory = SimpleClientFactory(profile)

    assert factory.queue.max_concurrent == 4

    # Two clients, as two hypotheses in flight would have, must not each get
    # the full ceiling.
    from sastsimi.contracts.refs import StoredDataRef
    from sastsimi.simple_runtime.provider import SimpleClaudeClient

    queue = CallQueue(max_concurrent=2)
    live = 0
    peak = 0

    class _Runner:
        async def execute(self, request: object) -> object:
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            live -= 1
            raise RuntimeError("stop after the gate")

    ref = StoredDataRef(
        stored_data_id="c" * 64,
        data_kind="artifact",
        content_hash="c" * 64,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        record_id=None,
    )
    clients = [
        SimpleClaudeClient(
            runner=_Runner(),  # type: ignore[arg-type]
            provider_profile_ref=ref,
            model="claude-sonnet-5",
            queue=queue,
        )
        for _ in range(6)
    ]
    results = await asyncio.gather(
        *(
            client.call(prompt=b"{}", output_schema={}, timeout_ms=1_000)
            for client in clients
        ),
        return_exceptions=True,
    )

    assert all(isinstance(result, RuntimeError) for result in results)
    assert peak == 2
