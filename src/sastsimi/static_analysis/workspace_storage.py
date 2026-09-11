"""Attempt-owned, quota-enforced workspace leases for repository preparation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import uuid
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.ports.dto import (
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
    WorkspaceStorageUsage,
)

_POLICY_FIELDS = frozenset(WorkspaceStoragePolicy.__dataclass_fields__) | {"kind"}
_MAX_POLICY_INTEGER = (1 << 63) - 1


class WorkspaceQuotaExceeded(RuntimeError):
    """The backend denied or observed a write beyond the immutable lease policy."""


def decode_workspace_storage_policy(
    policy_ref: RunStoredDataRef,
    raw: bytes,
    analysis_id: str,
) -> WorkspaceStoragePolicy:
    """Hash-verify and decode the one canonical pre-clone run artifact."""
    try:
        digest = hashlib.sha256(raw).hexdigest()
        if (
            not isinstance(policy_ref, RunStoredDataRef)
            or policy_ref.data_kind != "artifact"
            or policy_ref.record_id is not None
            or str(policy_ref.analysis_id) != analysis_id
            or str(policy_ref.stored_data_id) != digest
            or policy_ref.content_hash != digest
        ):
            raise ValueError
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != _POLICY_FIELDS:
            raise ValueError
        if (
            payload.get("kind") != "workspace_storage_policy"
            or payload.get("schema_version") != "1.0"
        ):
            raise ValueError
        values = tuple(
            payload[name]
            for name in _POLICY_FIELDS
            if name not in {"kind", "schema_version"}
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError
        if any(value > _MAX_POLICY_INTEGER for value in values):
            raise ValueError
        policy = WorkspaceStoragePolicy(
            **{name: payload[name] for name in payload if name != "kind"}
        )
        if canonical_bytes(payload) != raw:
            raise ValueError
        if (
            policy.max_git_bytes + policy.max_checkout_bytes + policy.min_free_bytes
            > _MAX_POLICY_INTEGER
        ):
            raise ValueError
        return policy
    except (
        KeyError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise ValueError("WORKSPACE_STORAGE_POLICY_INVALID") from error


class FixtureQuotaWorkspaceStorage:
    """Enforceable local fixture backend; production activation belongs to T16.

    The adapter deliberately refuses allocation unless the constructor's trusted
    backend capability probe says all limits are enforceable. Tests use this
    backend to exercise lease identity, quota accounting and cleanup semantics.
    """

    def __init__(
        self,
        root: Path,
        *,
        capacity_bytes: int,
        enforceable: bool = True,
    ) -> None:
        self._root = root
        self._capacity_bytes = capacity_bytes
        self._enforceable = enforceable
        self._leases: dict[
            str, tuple[WorkspaceStorageLease, WorkspaceStoragePolicy]
        ] = {}
        self._sealed: set[str] = set()

    def allocate(
        self,
        *,
        attempt_id: str,
        workspace_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
    ) -> WorkspaceStorageLease:
        if not self._enforceable:
            raise ValueError("WORKSPACE_QUOTA_UNENFORCEABLE")
        required = (
            policy.max_git_bytes + policy.max_checkout_bytes + policy.min_free_bytes
        )
        if required > self._capacity_bytes:
            self._root.mkdir(parents=True, exist_ok=True)
            raise ValueError("WORKSPACE_RESERVE_INSUFFICIENT")
        if not attempt_id or not workspace_id:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink():
            raise ValueError("WORKSPACE_LEASE_INVALID")
        lease_id = uuid.uuid4().hex
        target = self._root / lease_id
        target.mkdir(mode=0o700)
        lease = WorkspaceStorageLease(
            lease_id=lease_id,
            attempt_id=attempt_id,
            workspace_id=workspace_id,
            root=target.resolve(strict=True),
            backend_key="fixture-hard-quota-v1",
            policy_ref=policy_ref,
            enforcement_evidence=hashlib.sha256(
                canonical_bytes(
                    {
                        "backend": "fixture-hard-quota-v1",
                        "lease_id": lease_id,
                        "policy_hash": policy_ref.content_hash,
                    }
                )
            ).hexdigest(),
        )
        self._leases[lease_id] = (lease, policy)
        return lease

    def _registered(
        self, lease: WorkspaceStorageLease
    ) -> tuple[WorkspaceStorageLease, WorkspaceStoragePolicy]:
        registered = self._leases.get(lease.lease_id)
        if registered is None or registered[0] != lease:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        root = registered[0].root
        try:
            root.relative_to(self._root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise ValueError("WORKSPACE_LEASE_INVALID") from error
        return registered

    def measure(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage:
        registered, _ = self._registered(lease)
        if not registered.root.is_dir() or registered.root.is_symlink():
            raise ValueError("WORKSPACE_LEASE_INVALID")
        git_bytes = checkout_bytes = file_count = 0
        pending = [registered.root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    relative = path.relative_to(registered.root)
                    in_git = bool(relative.parts and relative.parts[0] == ".git")
                    details = entry.stat(follow_symlinks=False)
                    attributes = getattr(details, "st_file_attributes", 0)
                    link_like = entry.is_symlink() or bool(attributes & 0x400)
                    if not in_git:
                        file_count += 1
                    if link_like:
                        continue
                    if stat.S_ISDIR(details.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(details.st_mode):
                        if in_git:
                            git_bytes += details.st_size
                        else:
                            checkout_bytes += details.st_size
        used = git_bytes + checkout_bytes
        return WorkspaceStorageUsage(
            git_bytes=git_bytes,
            checkout_bytes=checkout_bytes,
            file_count=file_count,
            free_bytes=max(0, self._capacity_bytes - used),
        )

    def resolve(self, lease_id: str) -> WorkspaceStorageLease:
        registered = self._leases.get(lease_id)
        if registered is None:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        return self._registered(registered[0])[0]

    def enforce(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage:
        registered, policy = self._registered(lease)
        if registered.lease_id in self._sealed:
            raise ValueError("WORKSPACE_LEASE_SEALED")
        try:
            usage = self.measure(registered)
        except OSError as error:
            self.seal(registered, "STAT_ERROR")
            raise WorkspaceQuotaExceeded(
                "WORKSPACE_QUOTA_EXCEEDED:STAT_ERROR"
            ) from error
        reason = None
        if usage.git_bytes > policy.max_git_bytes:
            reason = "GIT_BYTES"
        elif usage.checkout_bytes > policy.max_checkout_bytes:
            reason = "CHECKOUT_BYTES"
        elif usage.file_count > policy.max_file_count:
            reason = "FILE_COUNT"
        elif usage.free_bytes < policy.min_free_bytes:
            reason = "FREE_RESERVE"
        if reason is not None:
            self.seal(registered, reason)
            raise WorkspaceQuotaExceeded("WORKSPACE_QUOTA_EXCEEDED:" + reason)
        return usage

    def seal(self, lease: WorkspaceStorageLease, reason: str) -> None:
        registered, _ = self._registered(lease)
        if not reason:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        self._sealed.add(registered.lease_id)

    def is_sealed(self, lease: WorkspaceStorageLease) -> bool:
        registered, _ = self._registered(lease)
        return registered.lease_id in self._sealed

    def cleanup_or_quarantine(self, lease: WorkspaceStorageLease) -> None:
        registered, _ = self._registered(lease)
        root = registered.root
        try:
            if root.is_symlink():
                raise OSError("linked lease root")
            shutil.rmtree(root)
        except OSError:
            self._sealed.add(registered.lease_id)
            return
        self._sealed.add(registered.lease_id)
