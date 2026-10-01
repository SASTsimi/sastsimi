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
from weakref import WeakValueDictionary

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attempt_owner import AttemptOwner, PromptByteCounts
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
    "CONTEXT_LIMIT_EXCEEDED",
    "CURSOR_AUTH_REQUIRED",
    "CURSOR_AUTH_FAILED",
    "CURSOR_CONFIGURATION_FAILED",
    "CURSOR_PLAN_LIMIT",
    "CURSOR_RATE_LIMITED",
    "CLAUDE_AUTH_REQUIRED",
    "CLAUDE_RATE_LIMITED",
)
_LOG = logging.getLogger(__name__)
_CODEX_CLEANUP_GRACE_SECONDS = 15.0
_BUDGET_GATES: WeakValueDictionary[tuple[str, str], asyncio.Lock] = (
    WeakValueDictionary()
)


def effective_hypothesis_concurrency(
    provider: str,
    configured: int,
    *,
    atomic_budget_reservations: bool = False,
    exact_child_claims: bool = False,
) -> int:
    """Bound child scheduling to independently established safety guarantees.

    The API allowance is for child tasks, not simultaneous billable requests:
    ``RunLimitedClient`` still holds its analysis budget gate through each call.
    The caller must hold the analysis run lease when asserting that gate provides
    atomic budget reservation, and must claim each child in the checkpoint store.
    """
    if type(configured) is not int or not 1 <= configured <= 32:
        raise ValueError("HYPOTHESIS_CONCURRENCY_INVALID")
    if (
        provider.strip().casefold() in {"openai", "openai-api"}
        and atomic_budget_reservations is True
        and exact_child_claims is True
    ):
        return configured
    return 1


def _analysis_budget_gate(
    store: SimpleCheckpointStore, analysis_id: str
) -> asyncio.Lock:
    """Share one in-process accounting gate across clients for a single analysis."""
    key = (str(store.database_path.resolve()), analysis_id)
    gate = _BUDGET_GATES.get(key)
    if gate is None:
        gate = asyncio.Lock()
        _BUDGET_GATES[key] = gate
    return gate


def _terminal(failure: StageFailure) -> bool:
    return any(fragment in failure.code.upper() for fragment in _TERMINAL_FRAGMENTS)


def _final_failure(failure: StageFailure) -> StageFailure:
    if failure.code == "INVALID_OUTPUT":
        return failure.model_copy(update={"retryable": False})
    return failure


def _unresolved_codex_call_failure() -> StageFailure:
    return StageFailure(
        code="CODEX_CALL_IN_FLIGHT_UNRESOLVED",
        retryable=False,
        safe_message="A prior Codex call requires process cleanup confirmation",
    )


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
        if (
            self._max_tokens != "unlimited"
            and int(summary["unknown_token_calls"] or 0) > 0
        ):
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
        self._budget_gate = _analysis_budget_gate(store, artifacts.identity.analysis_id)

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
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        if invocation_id is not None:
            raise ValueError("CODEX_CALL_ID_EXTERNALLY_SUPPLIED")
        if (
            owner is not None
            and owner.analysis_id != self._artifacts.identity.analysis_id
        ):
            raise ValueError("LLM_ATTEMPT_OWNER_INVALID")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1, timeout_ms) / 1000
        last_failure = StageFailure(
            code="TIMED_OUT",
            retryable=True,
            safe_message="LLM call deadline reached",
        )
        previous_attempt_id: str | None = None
        for attempt in range(1, self._max_retries + 2):
            async with self._budget_gate, self._semaphore:
                analysis_id = self._artifacts.identity.analysis_id
                if (
                    self._provider == "codex-cli"
                    and self._store.unresolved_codex_call(analysis_id) is not None
                ):
                    return _unresolved_codex_call_failure()
                budget_failure = self.budget_failure()
                if budget_failure is not None:
                    return budget_failure
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return _final_failure(last_failure)
                call_id = uuid4().hex if self._provider == "codex-cli" else None
                if call_id is not None and not self._store.begin_codex_call(
                    call_id, analysis_id
                ):
                    return _unresolved_codex_call_failure()

                def record_attempt(
                    agent: str,
                    attempt_number: int,
                    started_at: float,
                    status: str,
                    result: SimpleLLMCallResult | None,
                    failure: StageFailure | None = None,
                    *,
                    codex_call_id: str | None = call_id,
                ) -> None:
                    nonlocal previous_attempt_id
                    recorded_id = codex_call_id or uuid4().hex
                    self._record_attempt(
                        agent,
                        attempt_number,
                        started_at,
                        status,
                        result,
                        failure,
                        attempt_id=recorded_id,
                        owner=owner,
                        retry_of=previous_attempt_id,
                        prompt_bytes=prompt_bytes,
                    )
                    previous_attempt_id = recorded_id

                started = monotonic()
                inner_returned = False
                try:
                    if call_id is not None:
                        call = self._inner.call(
                            prompt=prompt,
                            output_schema=output_schema,
                            timeout_ms=max(1, int(remaining * 1000)),
                            agent_name=agent_name,
                            owner=owner,
                            prompt_bytes=prompt_bytes,
                            invocation_id=call_id,
                        )
                    elif owner is None and prompt_bytes is None:
                        call = self._inner.call(
                            prompt=prompt,
                            output_schema=output_schema,
                            timeout_ms=max(1, int(remaining * 1000)),
                            agent_name=agent_name,
                        )
                    else:
                        call = self._inner.call(
                            prompt=prompt,
                            output_schema=output_schema,
                            timeout_ms=max(1, int(remaining * 1000)),
                            agent_name=agent_name,
                            owner=owner,
                            prompt_bytes=prompt_bytes,
                        )
                    result = await asyncio.wait_for(
                        call,
                        # The Codex runner owns its request timeout and may still
                        # need to confirm child-process cleanup after it expires.
                        timeout=remaining
                        + (
                            _CODEX_CLEANUP_GRACE_SECONDS
                            if self._provider == "codex-cli"
                            else 0.0
                        ),
                    )
                    inner_returned = True
                except asyncio.CancelledError:
                    record_attempt(
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
                    record_attempt(
                        agent_name,
                        attempt,
                        started,
                        "SUCCEEDED",
                        result,
                    )
                    if call_id is not None:
                        self._store.mark_codex_call_safe(call_id, analysis_id)
                    return result
                terminal = _terminal(result)
                failure = (
                    result.model_copy(update={"retryable": False})
                    if terminal
                    else result
                )
                if failure.code == "INVALID_OUTPUT" and attempt > self._max_retries:
                    failure = failure.model_copy(update={"retryable": False})
                if failure.code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED":
                    failure = failure.model_copy(update={"retryable": False})
                record_attempt(
                    agent_name,
                    attempt,
                    started,
                    failure.code,
                    None,
                    failure,
                )
                if call_id is not None:
                    if (
                        not inner_returned
                        or failure.code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
                    ):
                        return (
                            failure
                            if inner_returned
                            else _unresolved_codex_call_failure()
                        )
                    self._store.mark_codex_call_safe(call_id, analysis_id)
                if failure.retryable and attempt <= self._max_retries:
                    # A billable failure without usage must block a retry even when
                    # the call deadline expires before the backoff can begin.
                    budget_failure = self.budget_failure()
                    if budget_failure is not None:
                        return budget_failure
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
        *,
        attempt_id: str | None = None,
        owner: AttemptOwner | None = None,
        retry_of: str | None = None,
        prompt_bytes: PromptByteCounts | None = None,
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
            attempt_id=attempt_id or uuid4().hex,
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
            owner=owner,
            retry_of=retry_of,
            prompt_bytes=prompt_bytes,
        )
