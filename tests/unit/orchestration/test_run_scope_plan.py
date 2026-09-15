from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import AnalysisId, OpaqueId, ProgramId, WorkspaceId
from sastsimi.orchestration.run_scope_plan import ProductionRunScopeAllocator
from sastsimi.ports.dto import RepositoryPreparation
from sastsimi.storage.artifact_store import LocalArtifactStore


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"id-{self.value}")


def _request(commit: str) -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref="https://example.invalid/repository.git",
        requested_git_ref=commit,
        program_id=ProgramId("program"),
        purpose=Purpose.PRODUCTION,
    )


def test_run_scope_is_allocated_before_clone_and_accepts_only_exact_checkout() -> None:
    allocator = ProductionRunScopeAllocator(_Ids())
    scope = allocator.allocate(_request("A" * 40))

    assert scope.analysis_id == AnalysisId("id-1")
    assert scope.workspace_id == WorkspaceId("id-2")
    assert str(scope.commit_id) == "a" * 40
    checkout = RepositoryPreparation(
        analysis_id="id-1",
        workspace_id="id-2",
        repository_url="https://example.invalid/repository.git",
        requested_ref="a" * 40,
        status="READY",
        resolved_commit_id="a" * 40,
        root=Path("C:/workspace"),
        tracked_files=(),
        gaps=(),
        errors=(),
        lease_id="lease",
    )
    allocator.require_checkout(scope, checkout)

    wrong = replace(scope, commit_id=type(scope.commit_id)("b" * 40))
    with pytest.raises(ValueError, match="CHECKOUT_SCOPE_MISMATCH"):
        allocator.require_checkout(wrong, checkout)


def test_concurrent_run_artifact_stores_never_share_mutable_scope(
    tmp_path: Path,
) -> None:
    allocator = ProductionRunScopeAllocator(_Ids())
    first = allocator.allocate(_request("a" * 40))
    second = allocator.allocate(_request("b" * 40))
    first_store = LocalArtifactStore(
        tmp_path / "artifacts", first.workspace_id, first.commit_id
    )
    second_store = LocalArtifactStore(
        tmp_path / "artifacts", second.workspace_id, second.commit_id
    )
    ref = first_store.commit(first_store.stage_bytes(b"first", "text/plain"))

    with pytest.raises(ValueError, match="WORKSPACE_MISMATCH"):
        second_store.open_verified(ref)
