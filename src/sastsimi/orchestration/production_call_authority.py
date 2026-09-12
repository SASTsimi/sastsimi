"""Exact production route selection and LLM call budget authority."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import BudgetProfileBinding, BudgetReservation
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
    PromptPayload,
    PromptRegistryEntry,
    ProviderProfile,
)
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    StoredDataRef,
    reference,
    require_record_ref,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.dto import Record
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.prompts.production import (
    ApprovedProductionRoute,
    PreparedProductionCall,
    ProductionRoute,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.debate_service import AuthorizedLLMCall


@dataclass(frozen=True, slots=True)
class AnalysisApprovedRoute:
    """One operator-approved route owned by exactly one analysis."""

    analysis_id: str
    route: ProductionRoute
    approval: ApprovedProductionRoute


class ExactAnalysisProductionRouteLookup:
    """Return only a current exact prompt/provider approval for one analysis."""

    def __init__(
        self,
        *,
        records: RecordStore,
        queries: RuntimeQueryPort,
        approvals: Iterable[AnalysisApprovedRoute],
    ) -> None:
        self._records = records
        self._queries = queries
        indexed: dict[tuple[str, str, str], AnalysisApprovedRoute] = {}
        for item in approvals:
            key = (item.analysis_id, str(item.route.role), item.route.task_kind)
            if not item.analysis_id.strip() or key in indexed:
                raise ValueError("PRODUCTION_LLM_ROUTE_APPROVAL_AMBIGUOUS")
            indexed[key] = item
        self._approvals = indexed

    def __call__(
        self, analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[ProductionRoute, ApprovedProductionRoute]:
        key = (analysis_id, str(role), task_kind)
        try:
            binding = self._approvals[key]
        except KeyError as error:
            raise ValueError("PRODUCTION_LLM_ROUTE_NOT_APPROVED") from error
        route, approval = binding.route, binding.approval
        if (
            binding.analysis_id != analysis_id
            or str(route.role) != str(role)
            or route.task_kind != task_kind
        ):
            raise ValueError("PRODUCTION_LLM_ROUTE_SCOPE_MISMATCH")

        active = self._current(approval.active_prompt_ref, analysis_id)
        evaluation = self._current(approval.evaluation_prompt_ref, analysis_id)
        recommendation = self._current(approval.quality_evaluation_ref, analysis_id)
        provider = self._current(approval.provider_profile_ref, analysis_id)
        if (
            not isinstance(active, PromptRegistryEntry)
            or active.status != "ACTIVE"
            or active.purpose != "PRODUCTION"
            or active.agent_role != role
            or active.task_kind != task_kind
            or active.prompt_key != route.prompt_key
            or active.quality_evaluation_ref != approval.quality_evaluation_ref
            or not isinstance(evaluation, PromptRegistryEntry)
            or evaluation.status != "ACTIVE"
            or evaluation.purpose != "EVALUATION"
            or evaluation.agent_role != role
            or evaluation.task_kind != task_kind
            or not isinstance(recommendation, EvaluationRecommendation)
            or recommendation.decision != "ACCEPT_FOR_PRODUCTION"
            or recommendation.target_prompt_registry_entry_ref
            != approval.evaluation_prompt_ref
            or recommendation.target_provider_profile_ref
            != approval.provider_profile_ref
            or recommendation.target_model != route.model
            or not isinstance(provider, ProviderProfile)
            or provider.support_status != "SUPPORTED"
            or provider.profile_key != route.provider_profile_key
            or provider.model != route.model
            or approval.provider_profile_ref not in active.provider_profile_refs
            or active.provider_profile_refs != evaluation.provider_profile_refs
        ):
            raise ValueError("PRODUCTION_LLM_ROUTE_APPROVAL_MISMATCH")
        return route, approval

    def _current(self, exact_ref: StoredDataRef, analysis_id: str) -> Record:
        try:
            value = self._records.get_exact(exact_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_LLM_ROUTE_NOT_APPROVED") from error
        meta = getattr(value, "meta", None)
        if (
            not isinstance(meta, RecordMeta)
            or str(meta.analysis_id) != analysis_id
            or reference(value) != exact_ref
        ):
            raise ValueError("PRODUCTION_LLM_ROUTE_SCOPE_MISMATCH")
        current = tuple(
            candidate
            for candidate in self._queries.current_records(
                analysis_id, str(meta.record_type)
            )
            if isinstance(candidate.meta, RecordMeta)
            and candidate.meta.logical_record_id == meta.logical_record_id
        )
        if len(current) != 1 or reference(current[0]) != exact_ref:
            raise ValueError("PRODUCTION_LLM_ROUTE_STALE")
        return value


class ProductionPreparedCallAuthorizer:
    """Create one CALL_LLM action under the run's exact active budget binding.

    A claimed call is never released speculatively. A returned invocation is
    accounted only when its persisted ``UsageMeasurement`` includes exact cost;
    otherwise its reservation remains RESERVED for recovery/reconciliation.
    """

    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        records: RecordStore,
        requester_identities: Mapping[tuple[str, LLMRole], BudgetScopeRef],
        reserved_cost_minor_units: int,
    ) -> None:
        if (
            isinstance(reserved_cost_minor_units, bool)
            or reserved_cost_minor_units <= 0
        ):
            raise ValueError("PRODUCTION_LLM_RESERVATION_COST_REQUIRED")
        self._runner = runner
        self._records = records
        self._identities = dict(requester_identities)
        self._reserved_cost_minor_units = reserved_cost_minor_units

    def authorize(
        self, *, work: WorkExecutionState, prepared: PreparedProductionCall
    ) -> AuthorizedLLMCall:
        spec, payload = self._prepared(work, prepared)
        analysis_id = str(work.meta.analysis_id)
        try:
            identity = self._identities[(analysis_id, spec.agent_role)]
        except KeyError as error:
            raise ValueError("PRODUCTION_LLM_IDENTITY_NOT_APPROVED") from error
        require_record_ref(identity)
        binding_ref = self._active_binding(work)
        action_inputs = llm_action_input_refs(prepared.call_spec_ref, spec, payload)
        action = self._runner.action(
            work,
            identity,
            str(spec.agent_role),
            ActionType.CALL_LLM,
            llm_call_spec_ref=prepared.call_spec_ref,
            provider_profile_ref=spec.provider_profile_ref,
            session_mode=spec.session_policy,
            input_refs=action_inputs,
        )
        reservation = self._runner.reserve(
            work,
            binding_ref,
            action,
            self._runner.units(
                elapsed_ms=spec.timeout_ms,
                llm_call_count=1,
                cost_minor_units=self._reserved_cost_minor_units,
            ),
        )
        decision_ref = self._runner.authorize(work, action, reservation)
        reservation_ref = reference(reservation)
        if not isinstance(decision_ref, StoredDataRef) or not isinstance(
            reservation_ref, StoredDataRef
        ):
            raise ValueError("PRODUCTION_LLM_AUTHORIZATION_SCOPE_MISMATCH")
        return AuthorizedLLMCall(
            work=work,
            decision_ref=decision_ref,
            reservation_ref=reservation_ref,
            call_spec_ref=prepared.call_spec_ref,
        )

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None:
        reservation = self._exact_reservation(call)
        result_ref = reference(invocation.result)
        request_ref = reference(invocation.request)
        if not isinstance(result_ref, StoredDataRef) or not isinstance(
            request_ref, StoredDataRef
        ):
            raise ValueError("PRODUCTION_LLM_USAGE_PROVENANCE_MISMATCH")
        try:
            stored_request = self._records.get_exact(request_ref)
            stored_result = self._records.get_exact(result_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_LLM_USAGE_PROVENANCE_MISMATCH") from error
        work = call.work
        if (
            stored_request != invocation.request
            or stored_result != invocation.result
            or not isinstance(stored_request, LLMInvocationRequest)
            or not isinstance(stored_result, LLMInvocationResult)
            or stored_request.call_spec_ref != call.call_spec_ref
            or stored_result.llm_call_id != stored_request.llm_call_id
            or any(
                getattr(stored_result.meta, field) != getattr(work.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                )
            )
            or stored_result.meta.attempt_id != work.active_attempt_id
            or stored_request.meta.attempt_id != work.active_attempt_id
        ):
            raise ValueError("PRODUCTION_LLM_USAGE_PROVENANCE_MISMATCH")
        if (
            invocation.dispatch_state == "UNRESOLVED"
            or stored_result.usage is None
            or stored_result.usage.cost_minor_units is None
        ):
            # Claimed/unknown-use reservations cannot be released as unused.
            return
        requests = stored_result.usage.provider_units.get("requests")
        if requests is not None and (
            isinstance(requests, bool) or not isinstance(requests, int) or requests != 1
        ):
            raise ValueError("PRODUCTION_LLM_USAGE_PROVENANCE_MISMATCH")
        cost = stored_result.usage.cost_minor_units
        if stored_result.usage.currency != reservation.requested_units.currency:
            raise ValueError("PRODUCTION_LLM_USAGE_CURRENCY_MISMATCH")
        actual = self._runner.units(
            elapsed_ms=stored_result.elapsed_ms,
            llm_call_count=1,
            cost_minor_units=cost,
        )
        self._runner.account(reservation, actual, usage_refs=(result_ref,))

    def _prepared(
        self, work: WorkExecutionState, prepared: PreparedProductionCall
    ) -> tuple[LLMCallSpec, PromptPayload]:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
        ):
            raise ValueError("PRODUCTION_LLM_ACTIVE_ATTEMPT_REQUIRED")
        try:
            spec = self._records.get_exact(prepared.call_spec_ref)
            payload = self._records.get_exact(prepared.payload_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_LLM_PREPARED_CALL_MISMATCH") from error
        if (
            not isinstance(spec, LLMCallSpec)
            or not isinstance(payload, PromptPayload)
            or spec != prepared.call_spec
            or payload != prepared.payload
            or reference(spec) != prepared.call_spec_ref
            or reference(payload) != prepared.payload_ref
            or spec.prompt_payload_ref != prepared.payload_ref
            or spec.meta.attempt_id != work.active_attempt_id
            or payload.meta.attempt_id != work.active_attempt_id
            or any(
                getattr(spec.meta, field) != getattr(work.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                )
            )
        ):
            raise ValueError("PRODUCTION_LLM_PREPARED_CALL_MISMATCH")
        return spec, payload

    def _active_binding(self, work: WorkExecutionState) -> StoredDataRef:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("PRODUCTION_LLM_BUDGET_BINDING_NOT_CURRENT")
        run = self._runner.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        binding_ref = run.budget_binding_ref
        if (
            not isinstance(run, AnalysisRunState)
            or run.status != "RUNNING"
            or binding_ref is None
            or run.meta.analysis_id != work.meta.analysis_id
            or run.workspace_id != work.meta.workspace_id
            or run.commit_id != work.meta.commit_id
        ):
            raise ValueError("PRODUCTION_LLM_BUDGET_BINDING_NOT_CURRENT")
        try:
            binding = self._records.get_exact(binding_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_LLM_BUDGET_BINDING_NOT_CURRENT") from error
        if (
            not isinstance(binding, BudgetProfileBinding)
            or reference(binding) != binding_ref
            or binding.status != "ACTIVE"
            or binding.purpose != run.purpose
            or binding.execution_budget_profile_ref != run.execution_budget_profile_ref
            or (
                binding.meta.analysis_id,
                binding.meta.workspace_id,
                binding.meta.commit_id,
            )
            != (
                work.meta.analysis_id,
                work.meta.workspace_id,
                work.meta.commit_id,
            )
        ):
            raise ValueError("PRODUCTION_LLM_BUDGET_BINDING_NOT_CURRENT")
        return binding_ref

    def _exact_reservation(self, call: AuthorizedLLMCall) -> BudgetReservation:
        try:
            reservation = self._records.get_exact(call.reservation_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PRODUCTION_LLM_RESERVATION_MISMATCH") from error
        if (
            not isinstance(reservation, BudgetReservation)
            or reference(reservation) != call.reservation_ref
            or reservation.status != "RESERVED"
            or reservation.requested_units.llm_call_count != 1
            or reservation.work_ref != reference(call.work)
        ):
            raise ValueError("PRODUCTION_LLM_RESERVATION_MISMATCH")
        return reservation


__all__ = [
    "AnalysisApprovedRoute",
    "ExactAnalysisProductionRouteLookup",
    "ProductionPreparedCallAuthorizer",
]
