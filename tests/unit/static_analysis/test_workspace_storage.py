"""Attempt-owned workspace quota and cleanup behavior."""

from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.ports.dto import WorkspaceStoragePolicy
from sastsimi.static_analysis.workspace_storage import (
    FixtureQuotaWorkspaceStorage,
    WorkspaceQuotaExceeded,
    decode_workspace_storage_policy,
)


def policy_bytes(**changes: int | str) -> bytes:
    return canonical_bytes(
        {
            "kind": "workspace_storage_policy",
            "schema_version": "1.0",
            "max_git_bytes": 10,
            "max_checkout_bytes": 20,
            "max_file_count": 2,
            "min_free_bytes": 30,
        }
        | changes
    )


def policy_ref(raw: bytes, *, analysis_id: str = "analysis") -> RunStoredDataRef:
    import hashlib

    digest = hashlib.sha256(raw).hexdigest()
    return RunStoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        analysis_id=AnalysisId(analysis_id),
        record_id=None,
    )


def test_policy_requires_exact_current_run_artifact_and_canonical_bytes() -> None:
    """Dropping any exact-ref check would permit caller-raised pre-clone limits."""
    raw = policy_bytes()
    ref = policy_ref(raw)
    assert decode_workspace_storage_policy(ref, raw, "analysis") == (
        WorkspaceStoragePolicy("1.0", 10, 20, 2, 30)
    )

    bad_refs: tuple[object, ...] = (
        ref.model_copy(update={"analysis_id": "other"}),
        ref.model_copy(update={"data_kind": "workspace_storage_policy"}),
        ref.model_copy(update={"stored_data_id": "f" * 64}),
        ref.model_copy(update={"content_hash": "f" * 64}),
        StoredDataRef(
            stored_data_id=ref.stored_data_id,
            data_kind="artifact",
            content_hash=ref.content_hash,
            workspace_id=WorkspaceId("workspace"),
            commit_id=CommitId("commit"),
            record_id=None,
        ),
    )
    for bad in bad_refs:
        with pytest.raises(ValueError, match="WORKSPACE_STORAGE_POLICY_INVALID"):
            decode_workspace_storage_policy(bad, raw, "analysis")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="WORKSPACE_STORAGE_POLICY_INVALID"):
        decode_workspace_storage_policy(ref, raw + b" ", "analysis")
    with pytest.raises(ValueError, match="WORKSPACE_STORAGE_POLICY_INVALID"):
        decode_workspace_storage_policy(ref, policy_bytes(max_git_bytes=0), "analysis")


def test_allocate_fails_closed_without_enforceable_backend_or_reserve(
    tmp_path: Path,
) -> None:
    """Replacing fail-closed allocation with a plain directory is a security bug."""
    raw = policy_bytes()
    ref = policy_ref(raw)
    policy = decode_workspace_storage_policy(ref, raw, "analysis")
    unavailable = FixtureQuotaWorkspaceStorage(
        tmp_path / "unavailable", capacity_bytes=100, enforceable=False
    )
    with pytest.raises(ValueError, match="WORKSPACE_QUOTA_UNENFORCEABLE"):
        unavailable.allocate(
            attempt_id="attempt",
            workspace_id="workspace",
            policy_ref=ref,
            policy=policy,
        )
    assert not (tmp_path / "unavailable").exists()

    insufficient = FixtureQuotaWorkspaceStorage(
        tmp_path / "insufficient", capacity_bytes=59
    )
    with pytest.raises(ValueError, match="WORKSPACE_RESERVE_INSUFFICIENT"):
        insufficient.allocate(
            attempt_id="attempt",
            workspace_id="workspace",
            policy_ref=ref,
            policy=policy,
        )
    assert list((tmp_path / "insufficient").glob("*")) == []


def test_lease_is_private_attempt_owned_and_limit_crossing_seals_it(
    tmp_path: Path,
) -> None:
    """A wrong counter or reusable overflowed lease would cross attempt boundaries."""
    raw = policy_bytes()
    ref = policy_ref(raw)
    policy = decode_workspace_storage_policy(ref, raw, "analysis")
    storage = FixtureQuotaWorkspaceStorage(tmp_path / "leases", capacity_bytes=100)
    lease = storage.allocate(
        attempt_id="attempt", workspace_id="workspace", policy_ref=ref, policy=policy
    )
    assert lease.root.is_dir()
    assert list(lease.root.iterdir()) == []
    assert lease.attempt_id == "attempt"
    assert lease.policy_ref == ref

    (lease.root / ".git").mkdir()
    (lease.root / ".git" / "objects").write_bytes(b"x" * 10)
    (lease.root / "one.py").write_bytes(b"y" * 20)
    usage = storage.enforce(lease)
    assert (usage.git_bytes, usage.checkout_bytes, usage.file_count) == (10, 20, 1)

    (lease.root / "two.py").write_bytes(b"z")
    with pytest.raises(WorkspaceQuotaExceeded, match="CHECKOUT_BYTES"):
        storage.enforce(lease)
    assert storage.is_sealed(lease)
    with pytest.raises(ValueError, match="WORKSPACE_LEASE_INVALID"):
        storage.enforce(replace(lease, attempt_id="other"))


def test_cleanup_targets_only_registered_exact_lease(tmp_path: Path) -> None:
    """Removing lease identity validation could recursively delete another root."""
    raw = policy_bytes()
    ref = policy_ref(raw)
    storage = FixtureQuotaWorkspaceStorage(tmp_path / "leases", capacity_bytes=100)
    lease = storage.allocate(
        attempt_id="attempt",
        workspace_id="workspace",
        policy_ref=ref,
        policy=decode_workspace_storage_policy(ref, raw, "analysis"),
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    forged = replace(lease, root=outside)
    with pytest.raises(ValueError, match="WORKSPACE_LEASE_INVALID"):
        storage.cleanup_or_quarantine(forged)
    assert outside.exists()
    storage.cleanup_or_quarantine(lease)
    assert not lease.root.exists()
