from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from typing import BinaryIO

import pytest

from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetRemaining,
    BudgetReservation,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, OpaqueId
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.records import RecordMeta, RecordMetadata, RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
    validate_exact_ref,
)
from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports import (
    ApprovedSandboxCommand,
    ArtifactStore,
    BudgetCommitRequest,
    BudgetLedgerPort,
    BudgetReleaseRequest,
    BudgetReservationRequest,
    CancellationResult,
    CapabilityProbeResult,
    CleanupResult,
    Clock,
    IdGenerator,
    LLMProviderAdapter,
    OfficialPolicyFetchRequest,
    OfficialPolicySource,
    PolicySourcePort,
    Record,
    RecordStore,
    SandboxCleanupRequest,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPort,
    SandboxPrepareRequest,
    StagedArtifact,
    StaticToolAdapter,
    StaticToolRequest,
    ToolCapabilityResult,
    ToolRunResult,
    TransitionCommitRequest,
    UnitOfWork,
    WorkContext,
    WorkHandler,
    WorkHandlerResult,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref as fixture_ref


class FakeClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 7, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 42


class FakeIds:
    def new[T: OpaqueId](self, kind: type[T]) -> T:
        return kind("deterministic")


class FakeRecords:
    def __init__(self, entries: tuple[tuple[RecordRef, Record], ...] = ()) -> None:
        self.entries = entries

    def get_exact(self, ref: RecordRef) -> Record:
        for expected, record in self.entries:
            if expected.stored_data_id == ref.stored_data_id:
                validate_exact_ref(
                    ref,
                    record.meta,
                    expected.content_hash,
                    analysis_id=record.meta.analysis_id
                    if isinstance(record.meta, RunMeta)
                    else None,
                )
                return record
        raise LookupError(ref.record_id)

    def is_revision_descendant(
        self, earlier_ref: RecordRef, later_ref: RecordRef
    ) -> bool:
        earlier = self.get_exact(earlier_ref)
        current = self.get_exact(later_ref)
        if (
            type(earlier.meta) is not type(current.meta)
            or earlier.meta.logical_record_id != current.meta.logical_record_id
            or earlier.meta.record_type != current.meta.record_type
            or current.meta.revision_number < earlier.meta.revision_number
        ):
            return False
        by_record_id = {record.meta.record_id: record for _, record in self.entries}
        visited = set()
        while current.meta.record_id != earlier.meta.record_id:
            if (
                current.meta.record_id in visited
                or current.meta.previous_record_id is None
            ):
                return False
            visited.add(current.meta.record_id)
            predecessor = by_record_id.get(current.meta.previous_record_id)
            if predecessor is None:
                return False
            current = predecessor
        return True

    def stage_record(self, record: Record) -> RecordRef:
        raise NotImplementedError

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        return request.commit


class FakeArtifacts:
    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        raise NotImplementedError

    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef:
        raise NotImplementedError

    def open_verified(self, ref: StoredDataRef | RunStoredDataRef) -> BinaryIO:
        return BytesIO(b"verified")


class FakeUow:
    records: RecordStore = FakeRecords()
    artifacts: ArtifactStore = FakeArtifacts()

    def commit(self, request: TransitionCommitRequest) -> TransitionCommit:
        return self.records.commit_transition(request)

    def rollback(self) -> None:
        pass


class FakeHandler:
    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        return WorkHandlerResult(output_refs=())


class FakeLlm:
    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        return CapabilityProbeResult(evidence=candidate)

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        return LLMInvocationResult.model_validate(
            {
                "meta": request.meta.model_copy(
                    update={"record_type": "llm_invocation_result"}
                ),
                "llm_call_id": request.llm_call_id,
                "purpose": request.purpose,
                "status": "FAILED",
                "provider": "fake",
                "model": request.model,
                "actual_session_mode": "NEW",
                "session_ref": None,
                "response_ref": None,
                "parsed_output_ref": None,
                "usage": None,
                "started_at": request.meta.created_at,
                "finished_at": request.meta.created_at,
                "elapsed_ms": 0,
                "safe_error": "fake boundary",
            }
        )

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(cancelled=True, reason=None)


class FakePolicy:
    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource:
        raise NotImplementedError


class FakeStatic:
    async def probe(
        self, profile_ref: StoredDataRef | HostConfigurationRef
    ) -> ToolCapabilityResult:
        return ToolCapabilityResult(
            ref=profile_ref,
            available=False,
            tool_name="AST",
            tool_kind="STRUCTURE",
            executable_key="fake",
            observed_executable_sha256=None,
            observed_version=None,
            expected_version="fake",
            reason_code="FAKE",
        )

    async def run(self, request: StaticToolRequest) -> ToolRunResult:
        raise NotImplementedError

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(cancelled=True, reason=None)


def test_static_transport_and_lower_process_seams_are_frozen() -> None:
    from dataclasses import fields

    from sastsimi.ports.dto import (
        CanonicalRepositorySource,
        ProcessResult,
        ProcessSpec,
        StaticCapabilityObservation,
        StaticOutputQuotaBinding,
        StaticToolObservation,
        StaticToolRequest,
        ToolCapabilityResult,
        WorkspaceStorageLease,
        WorkspaceStoragePolicy,
    )
    from sastsimi.ports.static_tool import StaticOutputQuotaPort, StaticProcessAdapter
    from sastsimi.ports.workspace import WorkspaceStoragePort

    assert [field.name for field in fields(StaticToolRequest)] == [
        "action",
        "workspace",
        "tool_profile_ref",
        "analysis_config_ref",
        "rule_catalog_ref",
        "repository_profile_ref",
        "execution_selection_ref",
    ]
    for transport in (
        CanonicalRepositorySource,
        ProcessSpec,
        ProcessResult,
        StaticCapabilityObservation,
        StaticOutputQuotaBinding,
        ToolCapabilityResult,
        StaticToolObservation,
        WorkspaceStoragePolicy,
        WorkspaceStorageLease,
    ):
        assert "meta" not in {field.name for field in fields(transport)}
    quota_fields = {field.name for field in fields(StaticOutputQuotaBinding)}
    assert {"limit_breached", "breach_evidence"} <= quota_fields
    assert StaticProcessAdapter is not None
    assert StaticOutputQuotaPort is not None
    assert WorkspaceStoragePort is not None


class FakeSandbox:
    async def prepare(self, request: SandboxPrepareRequest) -> SandboxEnvironment:
        raise NotImplementedError

    async def execute(self, request: ApprovedSandboxCommand) -> SandboxCommandRecord:
        raise NotImplementedError

    async def cleanup(self, request: SandboxCleanupRequest) -> CleanupResult:
        raise NotImplementedError


class FakeBudget:
    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation:
        return request.reservation

    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry:
        return request.entry

    def release(self, request: BudgetReleaseRequest) -> BudgetReservation:
        return request.reservation

    def remaining(
        self, budget_scope_ref: BudgetScopeRef, analysis_id: str
    ) -> BudgetRemaining:
        raise LookupError(analysis_id)


# These assignments are also checked by strict mypy: every published signature
# is exercised by a structurally independent implementation.
clock: Clock = FakeClock()
ids: IdGenerator = FakeIds()
records: RecordStore = FakeRecords()
artifacts: ArtifactStore = FakeArtifacts()
uow: UnitOfWork = FakeUow()
handler: WorkHandler = FakeHandler()
llm: LLMProviderAdapter = FakeLlm()
policy: PolicySourcePort = FakePolicy()
static: StaticToolAdapter = FakeStatic()
sandbox: SandboxPort = FakeSandbox()
budget: BudgetLedgerPort = FakeBudget()


@pytest.mark.parametrize(
    "port,implementation",
    [
        (Clock, clock),
        (IdGenerator, ids),
        (RecordStore, records),
        (ArtifactStore, artifacts),
        (UnitOfWork, uow),
        (WorkHandler, handler),
        (LLMProviderAdapter, llm),
        (PolicySourcePort, policy),
        (StaticToolAdapter, static),
        (SandboxPort, sandbox),
        (BudgetLedgerPort, budget),
    ],
)
def test_protocol_substitutability(port: type[object], implementation: object) -> None:
    assert isinstance(implementation, port)


@pytest.mark.asyncio
async def test_async_boundaries_are_awaitable() -> None:
    from sastsimi.contracts.ids import AnalysisId

    profile_payload = make("ProviderProfile", "provider_profile")
    profile_payload["validation_evidence_ref"] = fixture_ref(
        "provider_validation_evidence"
    )
    profile = ProviderProfile.model_validate_json(canonical_bytes(profile_payload))
    candidate = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    )
    request = LLMInvocationRequest.model_validate_json(
        canonical_bytes(make("LLMInvocationRequest", "llm_invocation_request"))
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    assert (await llm.probe(candidate)).evidence == candidate
    assert (await llm.invoke(request)).llm_call_id == request.llm_call_id
    assert (await static.probe(profile_ref)).ref == profile_ref
    assert (await static.cancel("a1")).cancelled
    assert (await llm.cancel("call")).cancelled
    assert clock.now().utcoffset() is not None
    assert clock.monotonic_ms() == 42
    assert isinstance(ids.new(AnalysisId), AnalysisId)
    assert artifacts.stage_bytes(b"x", "text/plain").data == b"x"


@dataclass(frozen=True)
class ExampleRecord:
    meta: RecordMetadata


def test_store_fake_rejects_cross_scope_revision_and_hash() -> None:
    import json

    meta = RecordMeta.model_validate_json(
        '{"record_id":"r1","logical_record_id":"l1","record_type":"example","schema_version":"1.0.0","analysis_id":"a1","workspace_id":"w1","commit_id":"c1","hypothesis_id":null,"attempt_id":null,"revision_number":1,"previous_record_id":null,"created_at":"2026-09-07T00:00:00Z"}'
    )
    data = dict(
        stored_data_id="s1",
        data_kind="example",
        content_hash="a" * 64,
        workspace_id="w1",
        commit_id="c1",
        record_id="r1",
    )
    exact = StoredDataRef.model_validate_json(json.dumps(data))
    store: RecordStore = FakeRecords(((exact, ExampleRecord(meta=meta)),))
    assert store.get_exact(exact).meta == meta
    for key, value in [
        ("workspace_id", "w2"),
        ("commit_id", "c2"),
        ("record_id", "r2"),
        ("content_hash", "b" * 64),
        ("data_kind", "other"),
    ]:
        with pytest.raises(ValueError):
            store.get_exact(
                StoredDataRef.model_validate_json(json.dumps(data | {key: value}))
            )
