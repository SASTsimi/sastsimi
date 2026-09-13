"""Production policy preparation for one already-claimed POLICY_FETCH work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.agents.policy_parser import PolicyParserAgentOutcome
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import ErrorId
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import (
    OfficialPolicyFetchRequest,
    OfficialPolicySource,
    Record,
    WorkContext,
)
from sastsimi.ports.policy_source import PolicySourcePort
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .adapters.official_http import PolicyFetchError, PolicySourceBoundaryError
from .cache_service import PolicyCacheService
from .collector import CollectedPolicy, PolicyCollector
from .program_catalog import ProgramCatalog


class PolicyParserPort(Protocol):
    async def parse(
        self,
        *,
        work: WorkExecutionState,
        source_ref: StoredDataRef,
    ) -> PolicyParserAgentOutcome: ...


@dataclass(frozen=True, slots=True)
class PolicyPreparationResult:
    completed_work: WorkExecutionState
    records: CollectedPolicy


class PolicyPreparationService:
    """Resolve exact inputs, fetch/parse or reuse, then commit one frozen state."""

    def __init__(
        self,
        *,
        runtime: RuntimeServices,
        runner: WorkflowRunner,
        catalog: ProgramCatalog,
        source: PolicySourcePort,
        parser: PolicyParserPort,
        cache: PolicyCacheService,
        collector: PolicyCollector,
        collector_identity_ref: BudgetScopeRef,
        parser_identity_ref: BudgetScopeRef,
    ) -> None:
        self._runtime = runtime
        self._runner = runner
        self._catalog = catalog
        self._source = source
        self._parser = parser
        self._cache = cache
        self._collector = collector
        self._collector_identity_ref = collector_identity_ref
        self._parser_identity_ref = parser_identity_ref

    async def prepare(self, context: WorkContext) -> PolicyPreparationResult:
        work = context.work
        self._require_context(context)
        preparing = self._require_preparing(work)
        entry = self._catalog.resolve_policy_entry(preparing.program_id)
        if (
            entry.source_config_ref != preparing.source_config_ref
            or entry.parser_name != preparing.parser_name
            or entry.parser_version != preparing.parser_version
            or work.input_refs != (entry.source_config_ref,)
        ):
            raise ValueError("POLICY_CATALOG_WORK_MISMATCH")
        run = self._runtime.budget_registry.current_state(str(work.meta.analysis_id))

        try:
            cached = self._cache.current(entry, started_at=run.started_at)
        except (LookupError, ValueError):
            records = self._collector.failed(
                work=work,
                preparing=preparing,
                entry=entry,
                error_id=self._runner.ids.new(ErrorId),
                terminal_status="FAILED",
                run_started_at=run.started_at,
            )
            return self._complete(work, records, status="FAILED")
        if cached is not None:
            records = self._collector.reused(
                work=work,
                preparing=preparing,
                entry=entry,
                cached=cached,
                run_started_at=run.started_at,
            )
            return self._complete(work, records, status="SUCCEEDED")

        try:
            official = await self._fetch(work, entry.source_config_ref)
        except PolicySourceBoundaryError:
            records = self._collector.failed(
                work=work,
                preparing=preparing,
                entry=entry,
                error_id=self._runner.ids.new(ErrorId),
                terminal_status="FAILED",
                run_started_at=run.started_at,
            )
            return self._complete(work, records, status="FAILED")
        except PolicyFetchError:
            records = self._collector.failed(
                work=work,
                preparing=preparing,
                entry=entry,
                error_id=self._runner.ids.new(ErrorId),
                terminal_status="BLOCKED",
                run_started_at=run.started_at,
            )
            return self._complete(work, records, status="BLOCKED")

        parser_outcome = await self._parser.parse(
            work=work,
            source_ref=official.source_check.source_ref,
        )
        (parser_ref,) = self._runner.publish_intermediate(
            work,
            self._parser_identity_ref,
            RequesterRole.POLICY_PARSER,
            (parser_outcome.result,),
            action_input_refs=(
                official.source_check.source_ref,
                *parser_outcome.invocation_refs,
            ),
        )
        if not isinstance(parser_ref, StoredDataRef):
            raise ValueError("POLICY_PARSER_REFERENCE_MISMATCH")
        if (
            parser_outcome.result.status != "SUCCEEDED"
            or parser_outcome.content is None
        ):
            error_id = (
                parser_outcome.result.error_ids[0]
                if parser_outcome.result.error_ids
                else self._runner.ids.new(ErrorId)
            )
            records = self._collector.failed(
                work=work,
                preparing=preparing,
                entry=entry,
                error_id=error_id,
                terminal_status="FAILED",
                run_started_at=run.started_at,
                source_ref=official.source_check.source_ref,
                parser=parser_outcome.result,
                parser_ref=parser_ref,
            )
            return self._complete(work, records, status="FAILED")
        records = self._collector.collected(
            work=work,
            preparing=preparing,
            entry=entry,
            source_check=official.source_check,
            parser=parser_outcome.result,
            parser_ref=parser_ref,
            content=parser_outcome.content,
            run_started_at=run.started_at,
        )
        return self._complete(work, records, status="SUCCEEDED")

    async def _fetch(
        self,
        work: WorkExecutionState,
        source_config_ref: BudgetScopeRef,
    ) -> OfficialPolicySource:
        scope = self._runtime.work.registration_scope(str(work.work_id))
        action = self._runner.action(
            work,
            self._collector_identity_ref,
            RequesterRole.POLICY_COLLECTOR,
            "FETCH_POLICY",
            input_refs=(source_config_ref,),
        )
        units = self._runner.units(elapsed_ms=1, cost_minor_units=1)
        reservation = self._runner.reserve(work, scope, action, units)
        decision_ref = self._runner.authorize(work, action, reservation)
        request = OfficialPolicyFetchRequest(
            action=action,
            program_id=self._require_preparing(work).program_id,
            source_config_ref=source_config_ref,
        )

        async def fetch_known() -> OfficialPolicySource | Exception:
            try:
                return await self._source.fetch_official(request)
            except (PolicyFetchError, PolicySourceBoundaryError) as error:
                return error

        try:
            result, _claimed = await self._runtime.external.invoke_bound(
                str(work.work_id),
                decision_ref,
                reference(reservation),
                lambda _decision_ref: fetch_known(),
                idempotency_key=str(action.action_id),
            )
            if isinstance(result, Exception):
                raise result
            return result
        finally:
            self._runner.account(reservation, units)

    def _complete(
        self,
        work: WorkExecutionState,
        records: CollectedPolicy,
        *,
        status: str,
    ) -> PolicyPreparationResult:
        outputs = cast(tuple[Record, ...], records.outputs())
        completed = self._runner.complete(
            work,
            self._collector_identity_ref,
            RequesterRole.POLICY_COLLECTOR,
            outputs,
            status=status,
            error_ids=tuple(str(value) for value in records.collection.error_ids),
            gap_ids=tuple(str(value) for value in records.collection.gap_ids),
            action_input_refs=work.input_refs,
        )
        return PolicyPreparationResult(completed, records)

    def _require_preparing(self, work: WorkExecutionState) -> RunPolicyState:
        state = self._runtime.policy.current_state(str(work.meta.analysis_id))
        if state is None or state.status != "PREPARING":
            raise ValueError("POLICY_PREPARING_REQUIRED")
        pending = self._runtime.unit_of_work.records.get_exact(state.policy_work_ref)
        if not isinstance(pending, WorkExecutionState) or (
            pending.work_id != work.work_id
            or pending.input_hash != work.input_hash
            or pending.work_generation != work.work_generation
        ):
            raise ValueError("POLICY_PREPARING_WORK_MISMATCH")
        return state

    def _require_context(self, context: WorkContext) -> None:
        work, attempt = context.work, context.attempt
        current = self._runtime.work.get(str(work.work_id))
        current_attempts = tuple(
            value
            for value in self._runtime.queries.published_records(
                str(work.meta.analysis_id)
            )
            if isinstance(value, WorkAttempt)
            and value.work_id == work.work_id
            and value.attempt_id == work.active_attempt_id
            and value.status == "RUNNING"
        )
        if (
            current != work
            or work.status != "RUNNING"
            or work.work_type != "POLICY_FETCH"
            or work.active_attempt_id is None
            or attempt.status != "RUNNING"
            or attempt.work_id != work.work_id
            or attempt.attempt_id != work.active_attempt_id
            or attempt.input_hash != work.input_hash
            or current_attempts != (attempt,)
        ):
            raise ValueError("POLICY_WORK_CONTEXT_MISMATCH")


__all__ = [
    "PolicyParserPort",
    "PolicyPreparationResult",
    "PolicyPreparationService",
]
