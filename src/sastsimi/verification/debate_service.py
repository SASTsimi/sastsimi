"""Shared fake and production Pro/Con orchestration for every generation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

from sastsimi.agents.con_agent import ConAgent
from sastsimi.agents.pro import ArtifactReader, ProAgent
from sastsimi.contracts.actions import RequesterRole, SessionMode
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    VerificationBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.llm import LLMCallSpec, PromptPayload
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
    validate_evidence_sessions,
)
from sastsimi.contracts.work import (
    WorkExecutionState,
    WorkStatus,
    WorkType,
    validate_parent_work,
)
from sastsimi.ports.fake_workflow import ProviderInvoker, ProviderProber
from sastsimi.ports.llm_invocation import (
    InvocationMetadataFactory,
    PersistedLLMInvocation,
)
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.llm_call_service import (
    AnalysisRunStateResolver,
    LLMCallService,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True)
class FakeDebateResult:
    pro: ProEvidenceResult
    con: ConEvidenceResult
    pro_ref: StoredDataRef
    con_ref: StoredDataRef


@dataclass(frozen=True)
class AuthorizedLLMCall:
    """One already-authorized call bound to a running evidence child work."""

    work: WorkExecutionState
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class DebateResult:
    pro: ProEvidenceResult
    con: ConEvidenceResult
    pro_ref: StoredDataRef
    con_ref: StoredDataRef
    pro_session_ref: str
    con_session_ref: str
    pro_invocation: PersistedLLMInvocation
    con_invocation: PersistedLLMInvocation


@dataclass(frozen=True)
class EvidenceBranchResult:
    """One independently committed branch; the parent is joined elsewhere."""

    record: ProEvidenceResult | ConEvidenceResult
    output_ref: StoredDataRef
    session_ref: str
    invocation: PersistedLLMInvocation


class LLMInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


type ClaimIdFactory = Callable[[str], str]
type EvidenceParallelLimit = Callable[[WorkExecutionState], int]
type ResultPublisher = Callable[
    [
        WorkExecutionState,
        ProEvidenceResult | ConEvidenceResult,
        PersistedLLMInvocation,
    ],
    StoredDataRef,
]


class DebateIncompleteError(ValueError):
    """A branch failed; any independently valid opposite result stays published."""

    def __init__(
        self,
        failure_count: int,
        completed_refs: tuple[StoredDataRef, ...],
        *,
        pro_invocation: PersistedLLMInvocation | None = None,
        con_invocation: PersistedLLMInvocation | None = None,
    ) -> None:
        super().__init__("EVIDENCE_DEBATE_INCOMPLETE")
        self.failure_count = failure_count
        self.completed_refs = completed_refs
        self.pro_invocation = pro_invocation
        self.con_invocation = con_invocation


def run_fake_debate(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    owner_ref: StoredDataRef,
    orchestrator_ref: StoredDataRef,
    verification_work: WorkExecutionState,
    debate_inputs: tuple[StoredDataRef, ...],
    record_meta: Callable[..., RecordMeta],
    artifact: Callable[[str], RecordRef],
    stored_artifact: Callable[[str], StoredDataRef],
    now: Callable[[], datetime],
    provider_invoke: ProviderInvoker,
    provider_probe: ProviderProber,
) -> FakeDebateResult:
    """Register both branches first, then invoke each real fake provider path."""
    if (
        not isinstance(verification_work.meta, RecordMeta)
        or verification_work.meta.hypothesis_id is None
    ):
        raise TypeError("FAKE_DEBATE_HYPOTHESIS_SCOPE_REQUIRED")
    children: list[tuple[str, StoredDataRef, WorkExecutionState]] = []
    for role in ("PRO", "CON"):
        identity = evidence.stored_identity(RequesterRole(role))
        child = runner.start(
            scope,
            verification_work.meta,
            f"{role}_EVIDENCE",
            "HYPOTHESIS",
            str(verification_work.meta.hypothesis_id),
            owner_ref,
            role="VERIFICATION",
            inputs=debate_inputs,
            parent=reference(verification_work),
            generation=verification_work.work_generation,
        )
        children.append((role, identity, child))

    results: list[ProEvidenceResult | ConEvidenceResult] = []
    for role, identity, child in children:
        call_ref, provider_ref = register_fake_llm_call(
            runtime,
            evidence,
            record_meta,
            artifact,
            now(),
            provider_probe,
            runner=runner,
            work=child,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role=role,
            result_kind=f"{role.lower()}_evidence_result",
            task_kind=_EVIDENCE_TASK_BY_ROLE[role],
            context_refs=debate_inputs,
        )
        selected_role = RequesterRole(role)

        def build_output(
            _decision: StoredDataRef,
            selected_role: str = role,
            selected_work: WorkExecutionState = child,
        ) -> ProEvidenceResult | ConEvidenceResult:
            model = ProEvidenceResult if selected_role == "PRO" else ConEvidenceResult
            return model.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=runner.metadata(
                            verification_work.meta,
                            f"{selected_role.lower()}_evidence_result",
                            attempt_id=selected_work.active_attempt_id,
                        ),
                        role=selected_role,
                        parent_work_id=verification_work.work_id,
                        evidence_work_id=selected_work.work_id,
                        verification_generation=verification_work.work_generation,
                        llm_call_id=f"fake-{selected_role.lower()}-call",
                        debate_input_hash=content_hash(debate_inputs),
                        evidence=(),
                        summary=f"{selected_role} reviewed the exact fake path",
                        limitations=(),
                    )
                )
            )

        result, invocation = invoke_fake_provider(
            runtime=runtime,
            runner=runner,
            work=child,
            scope=scope,
            identity=identity,
            action_role=selected_role,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=stored_artifact,
            build_output=build_output,
            provider_invoke=provider_invoke,
        )
        if not isinstance(result, (ProEvidenceResult, ConEvidenceResult)):
            raise TypeError("FAKE_DEBATE_OUTPUT_MISMATCH")
        persist_fake_invocation(runtime, invocation)
        completed = runner.complete(child, identity, role, (result,))
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
        results.append(result)

    pro, con = results
    if not isinstance(pro, ProEvidenceResult) or not isinstance(con, ConEvidenceResult):
        raise TypeError("FAKE_DEBATE_ROLE_MISMATCH")
    pro_ref, con_ref = reference(pro), reference(con)
    if not isinstance(pro_ref, StoredDataRef) or not isinstance(con_ref, StoredDataRef):
        raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
    return FakeDebateResult(pro, con, pro_ref, con_ref)


_PRIVATE_DEBATE_INPUT_KINDS = frozenset(
    {
        "artifact",
        "pro_evidence_result",
        "con_evidence_result",
        "llm_call_spec",
        "llm_invocation_request",
        "llm_invocation_result",
        "llm_invocation_log",
        "prompt_payload",
    }
)

_EVIDENCE_TASK_BY_ROLE = {
    "PRO": "COLLECT_SUPPORT",
    "CON": "COLLECT_COUNTEREVIDENCE",
}


def _normalized_inputs(
    refs: tuple[StoredDataRef, ...],
) -> tuple[StoredDataRef, ...]:
    unique = {canonical_bytes(ref): ref for ref in refs}
    return tuple(unique[key] for key in sorted(unique))


class CurrentEvidenceParallelLimit:
    """Resolve the trusted limit from the current exact ACTIVE budget binding."""

    def __init__(
        self, *, records: ExactRecordReader, run_states: AnalysisRunStateResolver
    ) -> None:
        self._records = records
        self._run_states = run_states

    def __call__(self, work: WorkExecutionState) -> int:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("EVIDENCE_BUDGET_PROFILE_NOT_CURRENT")
        run = self._run_states.current_state(str(work.meta.analysis_id))
        binding_ref = run.budget_binding_ref
        if (
            not isinstance(run, AnalysisRunState)
            or run.status != "RUNNING"
            or binding_ref is None
            or run.meta.analysis_id != work.meta.analysis_id
            or run.workspace_id != work.meta.workspace_id
            or run.commit_id != work.meta.commit_id
        ):
            raise ValueError("EVIDENCE_BUDGET_PROFILE_NOT_CURRENT")
        binding = self._records.get_exact(binding_ref)
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
            raise ValueError("EVIDENCE_BUDGET_PROFILE_NOT_CURRENT")
        profile_ref = binding.verification_budget_profile_ref
        profile = self._records.get_exact(profile_ref)
        if (
            not isinstance(profile, VerificationBudgetProfile)
            or reference(profile) != profile_ref
            or profile.status != "ACTIVE"
            or (
                profile.meta.analysis_id,
                profile.meta.workspace_id,
                profile.meta.commit_id,
            )
            != (
                work.meta.analysis_id,
                work.meta.workspace_id,
                work.meta.commit_id,
            )
        ):
            raise ValueError("EVIDENCE_BUDGET_PROFILE_NOT_CURRENT")
        return profile.max_parallel_evidence_calls


class DebateService:
    """Run exact-input Pro/Con calls concurrently and join committed results."""

    run_fake = staticmethod(run_fake_debate)

    def __init__(
        self,
        *,
        records: ExactRecordReader,
        artifacts: ArtifactReader,
        llm_calls: LLMCallService | LLMInvoker,
        metadata_factory: InvocationMetadataFactory,
        claim_id_factory: ClaimIdFactory,
        publish_result: ResultPublisher,
        parallel_limit: EvidenceParallelLimit,
    ) -> None:
        self.records = records
        self.llm_calls = llm_calls
        self.publish_result = publish_result
        self.parallel_limit = parallel_limit
        self.pro = ProAgent(
            artifacts=artifacts,
            metadata_factory=metadata_factory,
            claim_id_factory=claim_id_factory,
        )
        self.con = ConAgent(
            artifacts=artifacts,
            metadata_factory=metadata_factory,
            claim_id_factory=claim_id_factory,
        )

    async def run(
        self,
        *,
        verification_work: WorkExecutionState,
        public_input_refs: tuple[StoredDataRef, ...],
        pro_call: AuthorizedLLMCall,
        con_call: AuthorizedLLMCall,
    ) -> DebateResult:
        public_inputs = tuple(public_input_refs)
        if (
            not isinstance(verification_work.meta, RecordMeta)
            or verification_work.meta.hypothesis_id is None
            or verification_work.work_type != WorkType.VERIFICATION
            or verification_work.status != WorkStatus.RUNNING
            or verification_work.active_attempt_id is None
            or verification_work.input_hash != content_hash(public_inputs)
            or len(public_inputs) != len(set(public_inputs))
        ):
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH")
        if not public_inputs or any(
            ref.data_kind in _PRIVATE_DEBATE_INPUT_KINDS for ref in public_inputs
        ):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        if tuple(verification_work.input_refs) != public_inputs:
            raise ValueError("EVIDENCE_INPUT_CLOSURE_MISMATCH")
        pro_spec = self._validate_call(
            pro_call, "PRO", verification_work, public_inputs
        )
        con_spec = self._validate_call(
            con_call, "CON", verification_work, public_inputs
        )
        if (
            pro_call.work.work_id == con_call.work.work_id
            or pro_call.work.active_attempt_id == con_call.work.active_attempt_id
            or pro_spec.llm_call_id == con_spec.llm_call_id
            or pro_call.decision_ref == con_call.decision_ref
            or pro_call.reservation_ref == con_call.reservation_ref
            or pro_call.call_spec_ref == con_call.call_spec_ref
        ):
            raise ValueError("EVIDENCE_INDEPENDENCE_REQUIRED")

        parallel_limit = self.parallel_limit(verification_work)
        if isinstance(parallel_limit, bool) or parallel_limit < 1:
            raise ValueError("BUDGET_EXCEEDED: parallel evidence calls")
        capacity = asyncio.Semaphore(parallel_limit)
        invocations = await asyncio.gather(
            self._invoke_with_capacity(pro_call, capacity),
            self._invoke_with_capacity(con_call, capacity),
            return_exceptions=True,
        )
        debate_hash = content_hash(public_inputs)
        outputs: list[ProEvidenceResult | ConEvidenceResult | None] = [None, None]
        failures: list[Exception] = []
        for index, (call, invocation) in enumerate(
            ((pro_call, invocations[0]), (con_call, invocations[1]))
        ):
            if isinstance(invocation, BaseException):
                if not isinstance(invocation, Exception):
                    raise invocation
                failures.append(invocation)
                continue
            try:
                if (
                    invocation.request.call_spec_ref != call.call_spec_ref
                    or tuple(invocation.request.context_refs) != public_inputs
                ):
                    raise ValueError("EVIDENCE_INVOCATION_CLOSURE_MISMATCH")
                if index == 0:
                    outputs[index] = self.pro.finalize(
                        invocation,
                        parent_work=verification_work,
                        evidence_work=call.work,
                        debate_input_hash=debate_hash,
                        allowed_evidence_refs=public_inputs,
                    )
                else:
                    outputs[index] = self.con.finalize(
                        invocation,
                        parent_work=verification_work,
                        evidence_work=call.work,
                        debate_input_hash=debate_hash,
                        allowed_evidence_refs=public_inputs,
                    )
            except Exception as error:
                failures.append(error)

        completed_refs: list[StoredDataRef] = []
        if failures:
            publish_failures = 0
            for call, output, invocation in zip(
                (pro_call, con_call), outputs, invocations, strict=True
            ):
                if output is not None:
                    assert isinstance(invocation, PersistedLLMInvocation)
                    try:
                        completed_refs.append(
                            self._publish_exact(call.work, output, invocation)
                        )
                    except Exception:
                        publish_failures += 1
            raise DebateIncompleteError(
                len(failures) + publish_failures,
                tuple(completed_refs),
                pro_invocation=(
                    invocations[0]
                    if isinstance(invocations[0], PersistedLLMInvocation)
                    else None
                ),
                con_invocation=(
                    invocations[1]
                    if isinstance(invocations[1], PersistedLLMInvocation)
                    else None
                ),
            )

        pro = outputs[0]
        con = outputs[1]
        if not isinstance(pro, ProEvidenceResult) or not isinstance(
            con, ConEvidenceResult
        ):
            raise ValueError("FAKE_DEBATE_ROLE_MISMATCH")
        pro_invocation = cast(PersistedLLMInvocation, invocations[0])
        con_invocation = cast(PersistedLLMInvocation, invocations[1])
        pro_session = pro_invocation.result.session_ref
        con_session = con_invocation.result.session_ref
        assert pro_session is not None and con_session is not None
        completed_refs = []
        try:
            validate_evidence_sessions(
                pro,
                con,
                pro_session_id=pro_session,
                con_session_id=con_session,
                pro_mode=SessionMode(pro_invocation.request.session_policy),
                con_mode=SessionMode(con_invocation.request.session_policy),
            )
            pro_ref = self._publish_exact(pro_call.work, pro, pro_invocation)
            completed_refs.append(pro_ref)
            con_ref = self._publish_exact(con_call.work, con, con_invocation)
        except Exception as error:
            raise DebateIncompleteError(
                1,
                tuple(completed_refs),
                pro_invocation=pro_invocation,
                con_invocation=con_invocation,
            ) from error
        return DebateResult(
            pro,
            con,
            pro_ref,
            con_ref,
            pro_session,
            con_session,
            pro_invocation,
            con_invocation,
        )

    async def run_branch(
        self,
        *,
        parent_work: WorkExecutionState,
        public_input_refs: tuple[StoredDataRef, ...],
        call: AuthorizedLLMCall,
        role: str,
    ) -> EvidenceBranchResult:
        """Run one claimed branch without waiting for its sibling worker.

        A parent may still be PENDING while both children run.  The caller's
        non-blocking completion hook promotes that parent only after both exact
        branch results are committed.
        """

        if role not in {"PRO", "CON"}:
            raise ValueError("FAKE_DEBATE_ROLE_MISMATCH")
        public_inputs = _normalized_inputs(public_input_refs)
        if (
            not isinstance(parent_work.meta, RecordMeta)
            or parent_work.meta.hypothesis_id is None
            or parent_work.work_type != WorkType.VERIFICATION
            or parent_work.status not in {WorkStatus.PENDING, WorkStatus.RUNNING}
            or not public_inputs
            or any(
                ref.data_kind in _PRIVATE_DEBATE_INPUT_KINDS for ref in public_inputs
            )
        ):
            raise ValueError("EVIDENCE_PARENT_WORK_SCOPE_MISMATCH")
        limit = self.parallel_limit(parent_work)
        if isinstance(limit, bool) or limit < 1:
            raise ValueError("BUDGET_EXCEEDED: parallel evidence calls")
        self._validate_call(call, role, parent_work, public_inputs)
        invocation = await self._invoke(call)
        if (
            invocation.request.call_spec_ref != call.call_spec_ref
            or tuple(invocation.request.context_refs) != public_inputs
        ):
            raise ValueError("EVIDENCE_INVOCATION_CLOSURE_MISMATCH")
        debate_hash = content_hash(public_inputs)
        output = (
            self.pro.finalize(
                invocation,
                parent_work=parent_work,
                evidence_work=call.work,
                debate_input_hash=debate_hash,
                allowed_evidence_refs=public_inputs,
            )
            if role == "PRO"
            else self.con.finalize(
                invocation,
                parent_work=parent_work,
                evidence_work=call.work,
                debate_input_hash=debate_hash,
                allowed_evidence_refs=public_inputs,
            )
        )
        output_ref = self._publish_exact(call.work, output, invocation)
        session_ref = invocation.result.session_ref
        if not session_ref:
            raise ValueError("EVIDENCE_NEW_SESSION_REQUIRED")
        return EvidenceBranchResult(output, output_ref, session_ref, invocation)

    async def _invoke(self, call: AuthorizedLLMCall) -> PersistedLLMInvocation:
        return await self.llm_calls.invoke(
            work=call.work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )

    async def _invoke_with_capacity(
        self, call: AuthorizedLLMCall, capacity: asyncio.Semaphore
    ) -> PersistedLLMInvocation:
        async with capacity:
            return await self._invoke(call)

    def _validate_call(
        self,
        call: AuthorizedLLMCall,
        role: str,
        parent: WorkExecutionState,
        public_inputs: tuple[StoredDataRef, ...],
    ) -> LLMCallSpec:
        work_type = WorkType.PRO_EVIDENCE if role == "PRO" else WorkType.CON_EVIDENCE
        task_kind = _EVIDENCE_TASK_BY_ROLE[role]
        child = call.work
        if (
            child.work_type != work_type
            or child.status != WorkStatus.RUNNING
            or child.work_generation != parent.work_generation
            or child.active_attempt_id is None
            or tuple(child.input_refs) != public_inputs
            or child.input_hash != content_hash(public_inputs)
        ):
            raise ValueError("EVIDENCE_WORK_SCOPE_MISMATCH")
        validate_parent_work(child, parent)
        value = self.records.get_exact(call.call_spec_ref)
        if not isinstance(value, LLMCallSpec) or reference(value) != call.call_spec_ref:
            raise ValueError("LLM_CALL_SPEC_EXACT_REF_REQUIRED")
        spec = value
        if any(
            ref.data_kind in _PRIVATE_DEBATE_INPUT_KINDS for ref in spec.context_refs
        ):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        if not isinstance(child.meta, RecordMeta) or (
            spec.agent_role != role
            or spec.task_kind != task_kind
            or spec.session_policy != "NEW"
            or spec.parent_session_ref is not None
            or spec.context_refs != public_inputs
            or spec.meta.analysis_id != child.meta.analysis_id
            or spec.meta.workspace_id != child.meta.workspace_id
            or spec.meta.commit_id != child.meta.commit_id
            or spec.meta.hypothesis_id != child.meta.hypothesis_id
            or spec.meta.attempt_id != child.active_attempt_id
        ):
            raise ValueError("EVIDENCE_CALL_SCOPE_MISMATCH")
        payload_value = self.records.get_exact(spec.prompt_payload_ref)
        if isinstance(payload_value, PromptPayload) and any(
            binding.source_ref.data_kind in _PRIVATE_DEBATE_INPUT_KINDS
            for binding in payload_value.context_bindings
        ):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        if (
            not isinstance(payload_value, PromptPayload)
            or reference(payload_value) != spec.prompt_payload_ref
            or payload_value.agent_role != role
            or payload_value.task_kind != task_kind
            or payload_value.purpose != spec.purpose
            or tuple(binding.source_ref for binding in payload_value.context_bindings)
            != public_inputs
        ):
            raise ValueError("EVIDENCE_PROMPT_INPUT_CLOSURE_MISMATCH")
        return spec

    def _publish_exact(
        self,
        work: WorkExecutionState,
        output: ProEvidenceResult | ConEvidenceResult,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        output_ref = self.publish_result(work, output, invocation)
        if output_ref != reference(output):
            raise ValueError("EVIDENCE_OUTPUT_COMMIT_MISMATCH")
        stored = self.records.get_exact(output_ref)
        if stored != output or reference(stored) != output_ref:
            raise ValueError("EVIDENCE_OUTPUT_COMMIT_MISMATCH")
        return output_ref


__all__ = [
    "AuthorizedLLMCall",
    "CurrentEvidenceParallelLimit",
    "DebateIncompleteError",
    "DebateResult",
    "DebateService",
    "EvidenceBranchResult",
    "EvidenceParallelLimit",
    "FakeDebateResult",
    "run_fake_debate",
]
