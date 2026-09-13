"""Attempt-owned, quota-enforced workspace leases for repository preparation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import cast

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


class ProductionWorkspaceStorage:
    """Durable lease storage backed by an operator-approved quota root.

    This adapter persists ownership and policy identity across process restarts.
    It does not invent quota capability: ``backend_key`` and
    ``enforcement_evidence`` must come from the separately approved host
    capability, and a different capability cannot reopen an existing lease.
    """

    def __init__(
        self,
        root: Path,
        *,
        capacity_bytes: int,
        backend_key: str,
        enforcement_evidence: str,
    ) -> None:
        if (
            capacity_bytes <= 0
            or not backend_key.strip()
            or not enforcement_evidence.strip()
            or root.is_symlink()
        ):
            raise ValueError("WORKSPACE_QUOTA_UNENFORCEABLE")
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._lease_root = self._root / "leases"
        self._quarantine_root = self._root / "quarantine"
        self._lease_root.mkdir(mode=0o700, exist_ok=True)
        self._quarantine_root.mkdir(mode=0o700, exist_ok=True)
        if self._lease_root.is_symlink() or self._quarantine_root.is_symlink():
            raise ValueError("WORKSPACE_QUOTA_UNENFORCEABLE")
        self._database = self._root / "workspace-leases.sqlite3"
        self._capacity_bytes = capacity_bytes
        self._backend_key = backend_key
        self._enforcement_evidence = enforcement_evidence
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workspace_lease (
                    lease_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL UNIQUE,
                    workspace_id TEXT NOT NULL,
                    root TEXT NOT NULL UNIQUE,
                    backend_key TEXT NOT NULL,
                    enforcement_evidence TEXT NOT NULL,
                    policy_ref BLOB NOT NULL,
                    policy BLOB NOT NULL,
                    sealed INTEGER NOT NULL DEFAULT 0,
                    seal_reason TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database, timeout=30)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _policy_bytes(policy: WorkspaceStoragePolicy) -> bytes:
        values = (
            policy.max_git_bytes,
            policy.max_checkout_bytes,
            policy.max_file_count,
            policy.min_free_bytes,
        )
        if (
            policy.schema_version != "1.0"
            or any(type(value) is not int or value <= 0 for value in values)
            or any(value > _MAX_POLICY_INTEGER for value in values)
            or policy.max_git_bytes + policy.max_checkout_bytes + policy.min_free_bytes
            > _MAX_POLICY_INTEGER
        ):
            raise ValueError("WORKSPACE_STORAGE_POLICY_INVALID")
        return canonical_bytes(asdict(policy))

    @staticmethod
    def _ref_bytes(policy_ref: RunStoredDataRef) -> bytes:
        return canonical_bytes(policy_ref)

    def _decode_row(
        self, row: tuple[object, ...]
    ) -> tuple[WorkspaceStorageLease, WorkspaceStoragePolicy, bool]:
        (
            lease_id,
            attempt_id,
            workspace_id,
            root_value,
            backend_key,
            evidence,
            ref_raw,
            policy_raw,
            sealed,
        ) = row
        try:
            if (
                not all(
                    isinstance(value, str)
                    for value in (
                        lease_id,
                        attempt_id,
                        workspace_id,
                        root_value,
                        backend_key,
                        evidence,
                    )
                )
                or not isinstance(ref_raw, bytes)
                or not isinstance(policy_raw, bytes)
                or type(sealed) is not int
                or sealed not in {0, 1}
                or backend_key != self._backend_key
                or evidence != self._enforcement_evidence
            ):
                raise ValueError
            lease_id = cast(str, lease_id)
            attempt_id = cast(str, attempt_id)
            workspace_id = cast(str, workspace_id)
            root_value = cast(str, root_value)
            policy_ref = RunStoredDataRef.model_validate_json(ref_raw)
            payload = json.loads(policy_raw)
            if not isinstance(payload, dict):
                raise ValueError
            policy = WorkspaceStoragePolicy(**payload)
            if (
                self._ref_bytes(policy_ref) != ref_raw
                or self._policy_bytes(policy) != policy_raw
            ):
                raise ValueError
            lease_path = Path(root_value).resolve(strict=True)
            lease_path.relative_to(self._lease_root.resolve(strict=True))
            if lease_path.is_symlink() or not lease_path.is_dir():
                raise ValueError
            lease = WorkspaceStorageLease(
                lease_id=lease_id,
                attempt_id=attempt_id,
                workspace_id=workspace_id,
                root=lease_path,
                backend_key=backend_key,
                policy_ref=policy_ref,
                enforcement_evidence=evidence,
            )
            return lease, policy, bool(sealed)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("WORKSPACE_LEASE_INVALID") from None

    def _row(self, lease_id: str) -> tuple[object, ...]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT lease_id, attempt_id, workspace_id, root, backend_key,
                       enforcement_evidence, policy_ref, policy, sealed
                FROM workspace_lease WHERE lease_id = ?
                """,
                (lease_id,),
            ).fetchone()
        if row is None:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        return tuple(row)

    def allocate(
        self,
        *,
        attempt_id: str,
        workspace_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
    ) -> WorkspaceStorageLease:
        if not attempt_id.strip() or not workspace_id.strip():
            raise ValueError("WORKSPACE_LEASE_INVALID")
        ref_raw = self._ref_bytes(policy_ref)
        policy_raw = self._policy_bytes(policy)
        lease_id = uuid.uuid4().hex
        target = self._lease_root / lease_id
        created = False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """
                SELECT lease_id, attempt_id, workspace_id, root, backend_key,
                       enforcement_evidence, policy_ref, policy, sealed
                FROM workspace_lease WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            if prior is not None:
                lease, stored_policy, sealed = self._decode_row(tuple(prior))
                if (
                    sealed
                    or lease.workspace_id != workspace_id
                    or lease.policy_ref != policy_ref
                    or stored_policy != policy
                ):
                    raise ValueError("WORKSPACE_LEASE_INVALID")
                connection.commit()
                return lease
            rows = connection.execute(
                "SELECT policy FROM workspace_lease WHERE sealed = 0"
            ).fetchall()
            reserved = 0
            minimum_free = policy.min_free_bytes
            for (stored_raw,) in rows:
                if not isinstance(stored_raw, bytes):
                    raise ValueError("WORKSPACE_LEASE_INVALID")
                stored = WorkspaceStoragePolicy(**json.loads(stored_raw))
                if self._policy_bytes(stored) != stored_raw:
                    raise ValueError("WORKSPACE_LEASE_INVALID")
                reserved += stored.max_git_bytes + stored.max_checkout_bytes
                minimum_free = max(minimum_free, stored.min_free_bytes)
            required = (
                reserved
                + policy.max_git_bytes
                + policy.max_checkout_bytes
                + minimum_free
            )
            if required > self._capacity_bytes:
                raise ValueError("WORKSPACE_RESERVE_INSUFFICIENT")
            target.mkdir(mode=0o700)
            created = True
            resolved = target.resolve(strict=True)
            resolved.relative_to(self._lease_root.resolve(strict=True))
            connection.execute(
                """
                INSERT INTO workspace_lease (
                    lease_id, attempt_id, workspace_id, root, backend_key,
                    enforcement_evidence, policy_ref, policy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease_id,
                    attempt_id,
                    workspace_id,
                    str(resolved),
                    self._backend_key,
                    self._enforcement_evidence,
                    ref_raw,
                    policy_raw,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            if created:
                shutil.rmtree(target, ignore_errors=True)
            raise
        finally:
            connection.close()
        return self.resolve(lease_id)

    def _registered(
        self, lease: WorkspaceStorageLease
    ) -> tuple[WorkspaceStorageLease, WorkspaceStoragePolicy, bool]:
        registered, policy, sealed = self._decode_row(self._row(lease.lease_id))
        if registered != lease:
            raise ValueError("WORKSPACE_LEASE_INVALID")
        return registered, policy, sealed

    def measure(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage:
        registered, _policy, _sealed = self._registered(lease)
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
        lease, _policy, sealed = self._decode_row(self._row(lease_id))
        if sealed:
            raise ValueError("WORKSPACE_LEASE_SEALED")
        return lease

    def enforce(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage:
        registered, policy, sealed = self._registered(lease)
        if sealed:
            raise ValueError("WORKSPACE_LEASE_SEALED")
        usage = self.measure(registered)
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
        self._registered(lease)
        if not reason.strip():
            raise ValueError("WORKSPACE_LEASE_INVALID")
        with self._connect() as connection:
            changed = connection.execute(
                """
                UPDATE workspace_lease SET sealed = 1, seal_reason = ?
                WHERE lease_id = ? AND sealed = 0
                """,
                (reason, lease.lease_id),
            ).rowcount
        if changed not in {0, 1}:
            raise ValueError("WORKSPACE_LEASE_INVALID")

    def cleanup_or_quarantine(self, lease: WorkspaceStorageLease) -> None:
        registered, _policy, _sealed = self._registered(lease)
        try:
            shutil.rmtree(registered.root)
        except OSError:
            destination = self._quarantine_root / registered.lease_id
            if destination.exists() or destination.is_symlink():
                raise ValueError("WORKSPACE_LEASE_INVALID") from None
            try:
                os.replace(registered.root, destination)
            except OSError:
                pass
        finally:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE workspace_lease SET sealed = 1 WHERE lease_id = ?",
                    (registered.lease_id,),
                )
