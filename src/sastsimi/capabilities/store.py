"""Small durable store and trusted approval authority for capability probes."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.trusted_evidence import UnprovenEvidence

from .models import CapabilityProbeReceipt

_SAFE_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class _SQLiteCapabilityProbeStore:
    """Persist sanitized probe receipts separately from repository analyses."""

    def __init__(self, path: Path, *, host_id: str) -> None:
        if _SAFE_HOST_ID.fullmatch(host_id) is None:
            raise ValueError("PROBE_HOST_MISMATCH")
        self.path = path
        self.host_id = host_id
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS probe_receipts (
                    probe_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authorized_capability_approvals (
                    approval_hash TEXT PRIMARY KEY,
                    probe_id TEXT NOT NULL UNIQUE,
                    host_id TEXT NOT NULL,
                    approval_payload TEXT NOT NULL,
                    FOREIGN KEY(probe_id) REFERENCES probe_receipts(probe_id)
                );
                CREATE TABLE IF NOT EXISTS published_capability_profiles (
                    probe_id TEXT PRIMARY KEY,
                    profile_ref TEXT NOT NULL,
                    FOREIGN KEY(probe_id) REFERENCES probe_receipts(probe_id)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def add(self, receipt: CapabilityProbeReceipt) -> None:
        if receipt.host_id != self.host_id or receipt.approved_profile_ref is not None:
            raise ValueError("PROBE_HOST_MISMATCH")
        payload = canonical_bytes(receipt).decode()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO probe_receipts"
                "(probe_id, host_id, payload) VALUES (?, ?, ?)",
                (receipt.probe_id, receipt.host_id, payload),
            )

    def get(self, probe_id: str) -> CapabilityProbeReceipt:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, host_id FROM probe_receipts WHERE probe_id = ?",
                (probe_id,),
            ).fetchone()
            if row is None:
                raise LookupError("CAPABILITY_PROBE_NOT_FOUND")
            receipt = CapabilityProbeReceipt.model_validate_json(row[0])
            if row[1] != self.host_id or receipt.host_id != self.host_id:
                raise ValueError("PROBE_HOST_MISMATCH")
            published = connection.execute(
                "SELECT profile_ref FROM published_capability_profiles "
                "WHERE probe_id = ?",
                (probe_id,),
            ).fetchone()
        if published is None:
            return receipt
        return receipt.model_copy(
            update={
                "approved_profile_ref": HostConfigurationRef.model_validate_json(
                    published[0]
                )
            }
        )

    def list(self) -> tuple[CapabilityProbeReceipt, ...]:
        with self._connect() as connection:
            ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT probe_id FROM probe_receipts "
                    "WHERE host_id = ? ORDER BY rowid",
                    (self.host_id,),
                )
            )
        return tuple(self.get(probe_id) for probe_id in ids)

    def authorize(self, evidence: CapabilityApprovalEvidence, probe_id: str) -> None:
        receipt = self.get(probe_id)
        if not receipt.activation_supported or receipt.status != "PASSED":
            raise ValueError("PROBE_NOT_ACTIVATABLE")
        approval_hash = content_hash(evidence)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO authorized_capability_approvals"
                "(approval_hash, probe_id, host_id, approval_payload) "
                "VALUES (?, ?, ?, ?)",
                (
                    approval_hash,
                    probe_id,
                    self.host_id,
                    canonical_bytes(evidence).decode(),
                ),
            )

    def pending_approval(self, probe_id: str) -> CapabilityApprovalEvidence | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT approval_payload FROM authorized_capability_approvals "
                "WHERE probe_id = ? AND host_id = ?",
                (probe_id, self.host_id),
            ).fetchone()
        if row is None:
            return None
        return CapabilityApprovalEvidence.model_validate_json(row[0])

    def revoke(self, approval_hash: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM authorized_capability_approvals "
                "WHERE approval_hash = ? AND host_id = ?",
                (approval_hash, self.host_id),
            )

    def is_authorized(self, evidence: CapabilityApprovalEvidence) -> bool:
        if evidence.host_id != self.host_id:
            return False
        digest = content_hash(evidence)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT probe_id FROM authorized_capability_approvals "
                "WHERE approval_hash = ? AND host_id = ?",
                (digest, self.host_id),
            ).fetchone()
            if row is None:
                return False
            receipt = self.get(str(row[0]))
        return (
            receipt.approval_target_hash == evidence.approval_target_hash
            and receipt.profile_key == evidence.profile_key
            and receipt.subject_key == evidence.subject_key
            and receipt.observed_version == evidence.observed_version
            and receipt.observed_sha256 == evidence.observed_sha256
            and receipt.execution_target_hash == evidence.execution_target_hash
        )

    def publish(self, probe_id: str, profile_ref: HostConfigurationRef) -> None:
        receipt = self.get(probe_id)
        if receipt.host_id != profile_ref.host_id:
            raise ValueError("PROBE_HOST_MISMATCH")
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT profile_ref FROM published_capability_profiles "
                "WHERE probe_id = ?",
                (probe_id,),
            ).fetchone()
            encoded = canonical_bytes(profile_ref).decode()
            if existing is not None:
                if str(existing[0]) != encoded:
                    raise ValueError("CAPABILITY_PUBLICATION_REF_MISMATCH")
                return
            connection.execute(
                "INSERT INTO published_capability_profiles(probe_id, profile_ref) "
                "VALUES (?, ?)",
                (probe_id, encoded),
            )

    def unpublish(self, probe_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM published_capability_profiles WHERE probe_id = ?",
                (probe_id,),
            )

    def approved_profile_ref(self, probe_id: str) -> HostConfigurationRef | None:
        return self.get(probe_id).approved_profile_ref


class _CapabilityProbeEvidenceAuthority(UnprovenEvidence):
    """Trust only exact approval records minted from this host's durable receipt."""

    def __init__(self, store: _SQLiteCapabilityProbeStore) -> None:
        self._store = store

    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return self._store.is_authorized(evidence)


__all__: list[str] = []
