"""Bounded run-shared queue for providers without an internal call gate."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from time import monotonic
from typing import Any
from uuid import uuid4

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import StageFailure
from .provider import (
    SimpleCodexClient,
    SimpleLLMCallResult,
    SimpleLLMClient,
    SimpleOpenAIClient,
)
from .store import SimpleCheckpointStore
from .usage_values import canonical_cost, cost_minor_units, token_count

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
_NO_MODEL_RESPONSE_STATUSES = (
    "AUTH_REQUIRED",
    "RATE_LIMITED",
    "OPENAI_SDK_UNAVAILABLE",
    "MODEL_OR_REQUEST_UNSUPPORTED",
    "CURSOR_AUTH_REQUIRED",
    "CURSOR_AUTH_FAILED",
    "CURSOR_CONFIGURATION_FAILED",
    "CURSOR_PLAN_LIMIT",
    "CURSOR_RATE_LIMITED",
    "CLAUDE_AUTH_REQUIRED",
    "CLAUDE_RATE_LIMITED",
)
_LOG = logging.getLogger(__name__)


def _terminal(failure: StageFailure) -> bool:
    return any(fragment in failure.code.upper() for fragment in _TERMINAL_FRAGMENTS)


def _final_failure(failure: StageFailure) -> StageFailure:
    if failure.code == "INVALID_OUTPUT":
        return failure.model_copy(update={"retryable": False})
    return failure


class RunUsageBudget:
    """Read the persisted attempt ledger before a potentially billable request."""

    def __init__(
        self,
        *,
        store: SimpleCheckpointStore,
        analysis_id: str,
        max_tokens: TokenLimit,
        max_cost_minor_units: int,
        max_elapsed_seconds: ElapsedLimit,
    ) -> None:
        self._store = store
        self._analysis_id = analysis_id
        self._max_tokens = max_tokens
        self._max_cost = max_cost_minor_units
        self._max_elapsed_seconds = max_elapsed_seconds

    def check(self) -> StageFailure | None:
        summary = self._store.usage_summary(self._analysis_id)
        tokens = int(summary["input_tokens"] or 0) + int(summary["output_tokens"] or 0)
        if self._max_tokens != "unlimited" and tokens >= self._max_tokens:
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
        if (
            self._max_elapsed_seconds != "unlimited"
            and self._store.llm_elapsed_ms(self._analysis_id)
            >= self._max_elapsed_seconds * 1000
        ):
            return StageFailure(
                code="LLM_ELAPSED_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="Analysis elapsed-time ceiling has been reached",
            )
        if self._max_tokens != "unlimited":
            with sqlite3.connect(self._store.database_path) as connection:
                unknown_tokens = connection.execute(
                    "SELECT 1 FROM simple_llm_attempts "
                    "WHERE analysis_id = ? "
                    "AND (input_tokens IS NULL OR output_tokens IS NULL) "
                    "AND status NOT IN ("
                    f"{','.join('?' for _ in _NO_MODEL_RESPONSE_STATUSES)}) "
                    "LIMIT 1",
                    (self._analysis_id, *_NO_MODEL_RESPONSE_STATUSES),
                ).fetchone()
            if unknown_tokens is not None:
                return StageFailure(
                    code="LLM_TOKEN_USAGE_UNAVAILABLE",
                    retryable=False,
                    safe_message="A previous LLM attempt did not report token usage",
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
        max_tokens: TokenLimit,
        max_cost_minor_units: int,
        max_elapsed_seconds: ElapsedLimit,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._inner = inner
        self._semaphore = semaphore
        self._artifacts = artifacts
        self._store = store
        self._model = model
        self._max_retries = min(max_retries, 2)
        self._provider = (
            "openai-api"
            if isinstance(inner, SimpleOpenAIClient)
            else "codex-cli"
            if isinstance(inner, SimpleCodexClient)
            else None
        )
        self._budget = RunUsageBudget(
            store=store,
            analysis_id=artifacts.identity.analysis_id,
            max_tokens=max_tokens,
            max_cost_minor_units=max_cost_minor_units,
            max_elapsed_seconds=max_elapsed_seconds,
        )
        self._sleep = sleep

    def budget_failure(self) -> StageFailure | None:
        failure = self._budget.check()
        if failure is not None:
            return failure
        if self._provider == "openai-api" and self._has_unknown_api_cost():
            return StageFailure(
                code="LLM_COST_USAGE_UNAVAILABLE",
                retryable=False,
                safe_message="A previous API attempt did not report a trusted cost",
            )
        return None

    def _has_unknown_api_cost(self) -> bool:
        with sqlite3.connect(self._store.database_path) as connection:
            rows = connection.execute(
                "SELECT status, artifact_ref_json FROM simple_llm_attempts "
                "WHERE analysis_id = ? AND cost_cents IS NULL",
                (self._artifacts.identity.analysis_id,),
            ).fetchall()
        for status, ref_json in rows:
            if status in _NO_MODEL_RESPONSE_STATUSES:
                continue
            try:
                ref = StoredDataRef.model_validate_json(ref_json)
                metadata = json.loads(self._artifacts.read(ref))
            except (OSError, TypeError, ValueError, sqlite3.Error):
                return True
            if not isinstance(metadata, dict):
                return True
            if metadata.get("provider") == "openai-api" or (
                metadata.get("kind") == "simple_llm_attempt"
                and metadata.get("provider") is None
            ):
                return True
        return False

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
                    return _final_failure(last_failure)
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
                if failure.code == "INVALID_OUTPUT" and attempt > self._max_retries:
                    failure = failure.model_copy(update={"retryable": False})
                self._record_attempt(
                    agent_name, attempt, started, failure.code, None, failure
                )
            last_failure = failure
            if not failure.retryable or attempt > self._max_retries:
                return failure
            delay = min(8.0, 0.5 * 2 ** (attempt - 1))
            if loop.time() + delay >= deadline:
                return _final_failure(failure)
            await self._sleep(delay)
        return _final_failure(last_failure)

    def _record_attempt(
        self,
        agent: str,
        attempt: int,
        started: float,
        status: str,
        result: SimpleLLMCallResult | None,
        failure: StageFailure | None = None,
    ) -> None:
        elapsed = max(0, int((monotonic() - started) * 1000))
        input_tokens = token_count(result.input_tokens) if result is not None else None
        output_tokens = (
            token_count(result.output_tokens) if result is not None else None
        )
        cost = cost_minor_units(result.cost_minor_units) if result is not None else None
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
            "provider": self._provider or (result.provider if result else None),
            "agent": agent,
            "model": self._model,
            "attempt": attempt,
            "status": status,
            "elapsed_ms": elapsed,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_minor_units": canonical_cost(cost),
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
            "evidence_refs": (
                [ref.model_dump(mode="json") for ref in failure.evidence_refs]
                if failure is not None
                else []
            ),
            "retryable": failure.retryable if failure is not None else None,
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
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_cents=cost,
            artifact_ref=ref,
        )
