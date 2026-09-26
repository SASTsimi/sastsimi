from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.storage.artifact_store import LocalArtifactStore

from .models import CheckpointIdentity

_MAX_CONTEXT_BYTES = 256 * 1024


class SimpleArtifactRepository:
    """Exact record reader plus content-addressed output writer."""

    def __init__(self, data_dir: str | Path, identity: CheckpointIdentity) -> None:
        self.data_dir = Path(data_dir)
        self.identity = identity
        self.paths = RuntimePaths(self.data_dir)
        self.artifacts = LocalArtifactStore(
            self.paths.artifacts,
            WorkspaceId(identity.workspace_id),
            CommitId(identity.commit_id),
        )

    def put_bytes(self, value: bytes, media_type: str) -> StoredDataRef:
        return self.artifacts.commit(self.artifacts.stage_bytes(value, media_type))

    def put_json(self, value: object) -> StoredDataRef:
        return self.put_bytes(canonical_bytes(value), "application/json")

    def read(self, ref: StoredDataRef) -> bytes:
        self._require_scope(ref)
        if ref.record_id is None:
            with self.artifacts.open_verified(ref) as stream:
                return stream.read()
        connection = sqlite3.connect(
            f"file:{self.paths.database.resolve().as_posix()}?mode=ro",
            uri=True,
        )
        try:
            row = connection.execute(
                "SELECT payload, ref FROM records WHERE record_id = ?",
                (str(ref.record_id),),
            ).fetchone()
        finally:
            connection.close()
        if row is None or StoredDataRef.model_validate_json(row[1]) != ref:
            raise ValueError("SIMPLE_RUNTIME_EXACT_REFERENCE_MISMATCH")
        payload = str(row[0]).encode("utf-8")
        if hashlib.sha256(payload).hexdigest() != ref.content_hash:
            raise ValueError("SIMPLE_RUNTIME_EXACT_REFERENCE_MISMATCH")
        return payload

    def prompt_context(self, refs: tuple[StoredDataRef, ...]) -> bytes:
        items: list[dict[str, Any]] = []
        used = 0
        for ref in refs:
            raw = self.read(ref)
            redacted = self._redacted(raw)
            remaining = _MAX_CONTEXT_BYTES - used
            if remaining <= 0:
                break
            redacted = redacted[:remaining]
            used += len(redacted)
            try:
                data: Any = json.loads(redacted)
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = redacted.decode("utf-8", errors="replace")
            item: dict[str, Any] = {
                "reference": ref.model_dump(mode="json"),
                "data": data,
            }
            if ref.data_kind == "code_context_response":
                item["code_fragments"] = self._code_fragments(
                    raw,
                    remaining - len(redacted),
                )
            items.append(item)
        return canonical_bytes({"exact_inputs": items})

    def prompt_context_strict(self, refs: tuple[StoredDataRef, ...]) -> bytes:
        """Return complete exact inputs or fail before any silent truncation."""

        items: list[dict[str, Any]] = []
        used = 0
        for ref in refs:
            raw = self.read(ref)
            redacted = self._redacted(raw)
            if not items and redacted != raw:
                raise ValueError("SIMPLE_RUNTIME_CONTEXT_REDACTED")
            payload = raw if not items else redacted
            used += len(payload)
            if used > _MAX_CONTEXT_BYTES:
                raise ValueError("SIMPLE_RUNTIME_CONTEXT_TOO_LARGE")
            try:
                data: Any = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = payload.decode("utf-8", errors="strict")
            items.append({"reference": ref.model_dump(mode="json"), "data": data})
        context = canonical_bytes({"exact_inputs": items})
        if len(context) > _MAX_CONTEXT_BYTES:
            raise ValueError("SIMPLE_RUNTIME_CONTEXT_TOO_LARGE")
        return context

    def published_refs(
        self,
        kinds: frozenset[str],
        *,
        hypothesis_id: str | None = None,
    ) -> tuple[StoredDataRef, ...]:
        connection = sqlite3.connect(
            f"file:{self.paths.database.resolve().as_posix()}?mode=ro",
            uri=True,
        )
        try:
            available_tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not {"records", "record_revisions"}.issubset(available_tables):
                return ()
            rows = connection.execute(
                """
                SELECT r.payload, r.ref
                FROM records AS r
                JOIN record_revisions AS published
                  ON published.record_id = r.record_id
                ORDER BY r.revision_number, r.record_id
                """
            ).fetchall()
        finally:
            connection.close()
        refs: list[StoredDataRef] = []
        for payload_json, ref_json in rows:
            payload = json.loads(payload_json)
            meta = payload.get("meta", {})
            if (
                meta.get("analysis_id") != self.identity.analysis_id
                or meta.get("record_type") not in kinds
                or (
                    hypothesis_id is not None
                    and meta.get("hypothesis_id") != hypothesis_id
                )
            ):
                continue
            try:
                ref = StoredDataRef.model_validate_json(ref_json)
                self._require_scope(ref)
            except ValueError:
                continue
            refs.append(ref)
        return tuple(refs)

    def _code_fragments(self, response: bytes, remaining: int) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        try:
            value = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return []
        fragments: list[dict[str, Any]] = []
        for raw_ref in value.get("code_fragment_refs", []):
            try:
                ref = StoredDataRef.model_validate(raw_ref)
                body = self._redacted(self.read(ref))
            except (OSError, ValueError):
                continue
            body = body[:remaining]
            remaining -= len(body)
            fragments.append(
                {
                    "reference": ref.model_dump(mode="json"),
                    "content": body.decode("utf-8", errors="replace"),
                }
            )
            if remaining <= 0:
                break
        return fragments

    @staticmethod
    def _redacted(raw: bytes) -> bytes:
        try:
            return redact_projected_json(raw).data
        except ValueError:
            return redact_untrusted_text(raw).data

    def _require_scope(self, ref: StoredDataRef) -> None:
        if (
            str(ref.workspace_id) != self.identity.workspace_id
            or str(ref.commit_id) != self.identity.commit_id
        ):
            raise ValueError("SIMPLE_RUNTIME_REFERENCE_SCOPE_MISMATCH")


__all__ = ["SimpleArtifactRepository"]
