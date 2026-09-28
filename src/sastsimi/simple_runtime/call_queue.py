"""Bounded run-shared queue for providers without an internal call gate."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from time import monotonic
from typing import Any
from uuid import uuid4

from .artifacts import SimpleArtifactRepository
from .models import StageFailure
from .provider import SimpleLLMCallResult, SimpleLLMClient
from .store import SimpleCheckpointStore

_TERMINAL_FRAGMENTS = (
    "AUTH",
    "MODEL",
    "BOUNDARY",
    "POLICY",
    "COUNTER_EVIDENCE",
    "SCOPE",
    "PERMISSION",
    "CREDENTIAL",
    "INVALID_REQUEST",
)
_LOG = logging.getLogger(__name__)


def _terminal(failure: StageFailure) -> bool:
    return any(fragment in failure.code.upper() for fragment in _TERMINAL_FRAGMENTS)


class RunUsageBudget:
    """Read the persisted attempt ledger before a potentially billable request."""

    def __init__(
        self,
        *,
        store: SimpleCheckpointStore,
        analysis_id: str,
        max_tokens: int,
        max_cost_minor_units: int,
        max_elapsed_seconds: int,
    ) -> None:
        self._store = store
        self._analysis_id = analysis_id
        self._max_tokens = max_tokens
        self._max_cost = max_cost_minor_units
        self._max_elapsed_seconds = max_elapsed_seconds

    def check(self) -> StageFailure | None:
        summary = self._store.usage_summary(self._analysis_id)
        tokens = int(summary["input_tokens"] or 0) + int(summary["output_tokens"] or 0)
        if tokens >= self._max_tokens:
            return StageFailure(
                code="LLM_TOKEN_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="Analysis token ceiling has been reached",
            )
        cost = summary["cost_minor_units"]
        if cost is not None and float(cost) >= self._max_cost:
            return StageFailure(
                code="LLM_COST_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="Analysis cost ceiling has been reached",
            )
        if self._store.llm_elapsed_ms(self._analysis_id) >= (
            self._max_elapsed_seconds * 1000
        ):
            return StageFailure(
                code="LLM_ELAPSED_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="Analysis elapsed-time ceiling has been reached",
            )
        return None


class RunLimitedClient:
    """Retry Codex/OpenAI calls under one run-level gate and durable attempt ledger."""

    def __init__(
        self,
        *,
        inner: SimpleLLMClient,
        semaphore: asyncio.Semaphore,
        artifacts: SimpleArtifactRepository,
        store: SimpleCheckpointStore,
        model: str,
        max_retries: int,
        max_tokens: int,
        max_cost_minor_units: int,
        max_elapsed_seconds: int,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._inner = inner
        self._semaphore = semaphore
        self._artifacts = artifacts
        self._store = store
        self._model = model
        self._max_retries = min(max_retries, 2)
        self._budget = RunUsageBudget(
            store=store,
            analysis_id=artifacts.identity.analysis_id,
            max_tokens=max_tokens,
            max_cost_minor_units=max_cost_minor_units,
            max_elapsed_seconds=max_elapsed_seconds,
        )
        self._sleep = sleep

    def budget_failure(self) -> StageFailure | None:
        return self._budget.check()

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1, timeout_ms) / 1000
        last_failure = StageFailure(
            code="TIMED_OUT",
            retryable=True,
            safe_message="LLM call deadline reached",
        )
        for attempt in range(1, self._max_retries + 2):
            async with self._semaphore:
                budget_failure = self.budget_failure()
                if budget_failure is not None:
                    return budget_failure
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return last_failure
                started = monotonic()
                try:
                    result = await asyncio.wait_for(
                        self._inner.call(
                            prompt=prompt,
                            output_schema=output_schema,
                            timeout_ms=max(1, int(remaining * 1000)),
                            agent_name=agent_name,
                        ),
                        timeout=remaining,
                    )
                except asyncio.CancelledError:
                    self._record_attempt(
                        agent_name,
                        attempt,
                        started,
                        "CANCELLED",
                        None,
                    )
                    raise
                except TimeoutError:
                    result = StageFailure(
                        code="TIMED_OUT",
                        retryable=True,
                        safe_message="LLM call deadline reached",
                    )
                except Exception:
                    result = StageFailure(
                        code="FAILED",
                        retryable=True,
                        safe_message="LLM request did not complete",
                    )
                if isinstance(result, SimpleLLMCallResult):
                    self._record_attempt(
                        agent_name,
                        attempt,
                        started,
                        "SUCCEEDED",
                        result,
                    )
                    return result
                terminal = _terminal(result)
                failure = (
                    result.model_copy(update={"retryable": False})
                    if terminal
                    else result
                )
                self._record_attempt(agent_name, attempt, started, failure.code, None)
            last_failure = failure
            if not failure.retryable or attempt > self._max_retries:
                return failure
            delay = min(8.0, 0.5 * 2 ** (attempt - 1))
            if loop.time() + delay >= deadline:
                return failure
            await self._sleep(delay)
        return last_failure

    def _record_attempt(
        self,
        agent: str,
        attempt: int,
        started: float,
        status: str,
        result: SimpleLLMCallResult | None,
    ) -> None:
        elapsed = max(0, int((monotonic() - started) * 1000))
        _LOG.info(
            "llm_call analysis_id=%s agent=%s model=%s attempt=%d "
            "elapsed_ms=%d status=%s",
            self._artifacts.identity.analysis_id,
            agent,
            self._model,
            attempt,
            elapsed,
            status,
        )
        metadata = {
            "kind": "simple_llm_attempt",
            "agent": agent,
            "model": self._model,
            "attempt": attempt,
            "status": status,
            "elapsed_ms": elapsed,
            "input_tokens": result.input_tokens if result else None,
            "output_tokens": result.output_tokens if result else None,
            "cost_minor_units": result.cost_minor_units if result else None,
            "raw_output_ref": (
                result.raw_output_ref.model_dump(mode="json")
                if result and result.raw_output_ref
                else None
            ),
            "parsed_output_ref": (
                result.parsed_output_ref.model_dump(mode="json")
                if result and result.parsed_output_ref
                else None
            ),
        }
        ref = self._artifacts.put_json(metadata)
        self._store.record_llm_attempt(
            attempt_id=uuid4().hex,
            analysis_id=self._artifacts.identity.analysis_id,
            agent=agent,
            model=self._model,
            attempt_number=attempt,
            status=status,
            elapsed_ms=elapsed,
            input_tokens=result.input_tokens if result else None,
            output_tokens=result.output_tokens if result else None,
            cost_cents=result.cost_minor_units if result else None,
            artifact_ref=ref,
        )
