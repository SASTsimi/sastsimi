"""Opaque, runtime-distinct IDs. Prefixes have no meaning."""

from pydantic import ConfigDict, RootModel

from .base import NonEmptyStr


class OpaqueId(RootModel[NonEmptyStr]):
    model_config = ConfigDict(strict=True, frozen=True, revalidate_instances="always")

    def __str__(self) -> str:
        return self.root


class AnalysisId(OpaqueId):
    pass


class WorkspaceId(OpaqueId):
    pass


class CommitId(OpaqueId):
    pass


class RecordId(OpaqueId):
    pass


class LogicalRecordId(OpaqueId):
    pass


class StoredDataId(OpaqueId):
    pass


class ProgramId(OpaqueId):
    pass


class HypothesisId(OpaqueId):
    pass


class ProposalId(OpaqueId):
    pass


class ReportId(OpaqueId):
    pass


class WorkId(OpaqueId):
    pass


class AttemptId(OpaqueId):
    pass


class TransitionId(OpaqueId):
    pass


class TransitionCommitId(OpaqueId):
    pass


class ActionId(OpaqueId):
    pass


class DecisionId(OpaqueId):
    pass


class GapId(OpaqueId):
    pass


class ErrorId(OpaqueId):
    pass


class ReservationId(OpaqueId):
    pass


class LedgerEntryId(OpaqueId):
    pass
