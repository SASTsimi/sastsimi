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
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.records import RecordMeta, RecordMetadata, RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    StoredDataRef,
    validate_exact_ref,
)
from sastsimi.contracts.work import TransitionCommit
from sastsimi.ports import (
    ApprovedSandboxCommand,
    ArtifactStore,
    BoundaryRecord,
    BudgetCommitRequest,
    BudgetLedgerPort,
    BudgetReleaseRequest,
    BudgetReservationRequest,
    CancellationResult,
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
    ToolRunResult,
    TransitionCommitRequest,
    UnitOfWork,
    WorkContext,
    WorkHandler,
    WorkHandlerResult,
)


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

    def stage_record(self, record: Record) -> RecordRef:
        raise NotImplementedError

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        return request.commit


class FakeArtifacts:
    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        raise NotImplementedError

    def open_verified(self, ref: StoredDataRef) -> BinaryIO:
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
    async def probe(self, profile: BoundaryRecord) -> BoundaryRecord:
        return profile

    async def invoke(self, request: BoundaryRecord) -> BoundaryRecord:
        return request

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(cancelled=True, reason=None)


class FakePolicy:
    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource:
        raise NotImplementedError


class FakeStatic:
    async def probe(self, profile_ref: StoredDataRef) -> BoundaryRecord:
        return BoundaryRecord(ref=profile_ref)

    async def run(self, request: StaticToolRequest) -> ToolRunResult:
        raise NotImplementedError

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(cancelled=True, reason=None)


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
    from sastsimi.contracts.refs import RunStoredDataRef

    ref = RunStoredDataRef.model_validate_json(
        '{"stored_data_id":"s1","data_kind":"provider_profile","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","analysis_id":"a1","record_id":"r1"}'
    )
    value = BoundaryRecord(ref=ref)
    assert (await llm.probe(value)).ref == ref
    assert (await llm.invoke(value)).ref == ref
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
