from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_ARCHIVE_BYTES,
    MAX_BUNDLE_FILE_BYTES,
    MAX_BUNDLE_MANIFEST_BYTES,
    ReportBundleManifest,
    parse_bundle_manifest,
    read_bundle_archive,
    read_bundle_file,
)
from sastsimi.storage.artifact_store import LocalArtifactStore

from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)

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

    def put_prompt_proposal(self, value: Mapping[str, Any]) -> StoredDataRef:
        """Keep the original locally while supplying a redacted proposal to agents."""

        if value.get("kind") != "simple_hypothesis_proposal":
            raise ValueError("HYPOTHESIS_PROPOSAL_KIND_INVALID")
        raw = canonical_bytes(value)
        safe = redact_projected_json(raw).data
        if safe == raw:
            return self.put_bytes(raw, "application/json")
        original_ref = self.put_bytes(raw, "application/json")
        projected = json.loads(safe)
        if not isinstance(projected, dict):
            raise ValueError("HYPOTHESIS_PROPOSAL_REDACTION_INVALID")
        projected["original_proposal_ref"] = original_ref.model_dump(mode="json")
        prompt_bytes = canonical_bytes(projected)
        if redact_projected_json(prompt_bytes).data != prompt_bytes:
            raise ValueError("HYPOTHESIS_PROPOSAL_REDACTION_INVALID")
        return self.put_bytes(prompt_bytes, "application/json")

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

    def read_prompt_proposal(self, ref: StoredDataRef) -> bytes:
        """Verify both the prompt-safe proposal and its original CAS evidence."""

        payload = self.read(ref)
        try:
            proposal = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("HYPOTHESIS_PROPOSAL_ORIGINAL_INVALID") from error
        if (
            not isinstance(proposal, dict)
            or proposal.get("kind") != "simple_hypothesis_proposal"
        ):
            raise ValueError("HYPOTHESIS_PROPOSAL_ORIGINAL_INVALID")
        self._require_proposal_original(proposal, payload)
        return payload

    def _require_proposal_original(
        self, proposal: Mapping[str, Any], safe_payload: bytes
    ) -> None:
        if "original_proposal_ref" not in proposal:
            return  # Existing unredacted proposals have no secondary CAS object.
        try:
            original_ref = StoredDataRef.model_validate(
                proposal["original_proposal_ref"]
            )
            original = self.read(original_ref)
            projected = json.loads(redact_projected_json(original).data)
            if not isinstance(projected, dict):
                raise ValueError("Invalid original proposal")
            projected["original_proposal_ref"] = original_ref.model_dump(mode="json")
            if canonical_bytes(projected) != safe_payload:
                raise ValueError("Proposal projection mismatch")
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise ValueError("HYPOTHESIS_PROPOSAL_ORIGINAL_INVALID") from error

    def quarantine_corrupt(
        self, ref: StoredDataRef, *, max_bytes: int | None = None
    ) -> bool:
        """Move only a verified-invalid CAS file aside before an exact retry."""

        if max_bytes is not None and max_bytes < 0:
            raise ValueError("SIMPLE_RUNTIME_ARTIFACT_LIMIT_INVALID")
        self._require_scope(ref)
        if (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ValueError("SIMPLE_RUNTIME_ARTIFACT_REF_INVALID")
        path = self.artifacts.path_for(ref.content_hash)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or not path.resolve(strict=True).is_relative_to(self.artifacts.root)
        ):
            raise ValueError("SIMPLE_RUNTIME_ARTIFACT_PATH_UNSAFE")
        # The scan reader may reject a historically valid large object. Hash
        # it in bounded memory before deciding to move this global CAS path.
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("SIMPLE_RUNTIME_ARTIFACT_PATH_UNSAFE")
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            closed = os.fstat(stream.fileno())
            if (opened.st_size, opened.st_mtime_ns) != (
                closed.st_size,
                closed.st_mtime_ns,
            ):
                raise ValueError("SIMPLE_RUNTIME_ARTIFACT_CHANGED")
        if digest == ref.content_hash:
            return False
        quarantine = self.paths.quarantine
        if quarantine.is_symlink() or not quarantine.resolve().is_relative_to(
            self.data_dir.resolve()
        ):
            raise ValueError("SIMPLE_RUNTIME_QUARANTINE_PATH_UNSAFE")
        destination = quarantine / f"{ref.content_hash}-{uuid4().hex}"
        os.replace(path, destination)
        return True

    def read_bounded(self, ref: StoredDataRef, max_bytes: int) -> bytes:
        """Read a bounded exact CAS object for public attachment delivery."""

        self._require_scope(ref)
        with self.artifacts.open_verified_bounded(ref, max_bytes) as stream:
            return stream.read()

    def verified_report_bundle(
        self,
        *,
        checkpoints: Mapping[SimpleStage, StageCheckpoint],
        finding_ref: StoredDataRef,
        display_id: str,
        scope_status: str,
        public_projection: Callable[[bytes], bytes],
    ) -> tuple[ReportBundleManifest, bytes]:
        """Bind every attachment to the current PoC, gates and report."""

        def required(stage: SimpleStage) -> StageCheckpoint:
            item = checkpoints.get(stage)
            if (
                item is None
                or item.identity != self.identity
                or item.status is not StageStatus.SUCCEEDED
                or item.stage_version != STAGE_VERSION[stage]
            ):
                raise ValueError("BUNDLE_CURRENT_STAGE_MISSING")
            return item

        finding = required(SimpleStage.FINDING_DONE)
        report = required(SimpleStage.REPORT_DONE)
        candidate = required(SimpleStage.POC_CANDIDATE_DONE)
        dynamic = required(SimpleStage.POC_EXECUTION_DONE)
        technical = required(SimpleStage.TECH_GATE_DONE)
        scope = required(SimpleStage.SCOPE_GATE_DONE)
        if (
            finding_ref not in finding.output_refs
            or finding_ref not in report.input_refs
            or report.bundle_manifest_ref is None
            or report.bundle_archive_ref is None
            or len(report.output_refs) < 2
            or len(candidate.output_refs) < 2
            or len(dynamic.output_refs) < 1
            or len(technical.output_refs) != 1
            or len(scope.output_refs) != 1
            or dynamic.validated_poc_ref is None
            or finding.validated_poc_ref != dynamic.validated_poc_ref
            or report.validated_poc_ref != dynamic.validated_poc_ref
        ):
            raise ValueError("BUNDLE_CURRENT_CLOSURE_INVALID")
        candidate_ref, content_ref = candidate.output_refs[:2]
        execution_ref = dynamic.output_refs[0]
        validated_ref = dynamic.validated_poc_ref
        candidate_data = json.loads(self.read(candidate_ref))
        execution_data = json.loads(self.read(execution_ref))
        validated_data = json.loads(self.read(validated_ref))
        if not all(
            isinstance(item, dict)
            for item in (candidate_data, execution_data, validated_data)
        ):
            raise ValueError("BUNDLE_POC_CLOSURE_INVALID")
        if (
            StoredDataRef.model_validate(candidate_data.get("content_ref"))
            != content_ref
            or StoredDataRef.model_validate(execution_data.get("candidate_ref"))
            != candidate_ref
            or StoredDataRef.model_validate(execution_data.get("content_ref"))
            != content_ref
            or StoredDataRef.model_validate(validated_data.get("candidate_ref"))
            != candidate_ref
            or StoredDataRef.model_validate(validated_data.get("content_ref"))
            != content_ref
            or StoredDataRef.model_validate(validated_data.get("execution_ref"))
            != execution_ref
            or execution_data.get("attempt_id") != dynamic.attempt_id
            or validated_data.get("attempt_id") != dynamic.attempt_id
        ):
            raise ValueError("BUNDLE_POC_CLOSURE_INVALID")
        stdout_ref = StoredDataRef.model_validate(execution_data.get("stdout_ref"))
        stderr_ref = StoredDataRef.model_validate(execution_data.get("stderr_ref"))
        expected_sources = {
            "finding": finding_ref,
            "poc": content_ref,
            "validated_poc": validated_ref,
            "execution": execution_ref,
            "technical": technical.output_refs[0],
            "scope": scope.output_refs[0],
            "stdout": stdout_ref,
            "stderr": stderr_ref,
        }
        raw_report = self.read(report.output_refs[1])
        if public_projection(raw_report) != raw_report:
            raise ValueError("BUNDLE_PUBLIC_REPORT_RESTRICTED")
        manifest = parse_bundle_manifest(
            self.read_bounded(report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES),
            finding_ref=finding_ref,
        )
        bundle_dir = self._verified_report_directory(report, manifest)
        if (
            manifest.analysis_id != self.identity.analysis_id
            or manifest.display_id != display_id
            or manifest.poc_original_sha256 != content_ref.content_hash
        ):
            raise ValueError("BUNDLE_ID_OR_POC_MISMATCH")

        def bounded(ref: StoredDataRef) -> bytes:
            return self.read_bounded(ref, MAX_BUNDLE_FILE_BYTES)

        provenance_raw, _ = read_bundle_file(
            manifest, "evidence/provenance.json", bounded
        )
        provenance = json.loads(provenance_raw)
        if not isinstance(provenance, dict):
            raise ValueError("BUNDLE_PROVENANCE_INVALID")
        sources = provenance.get("sources")
        coverage = provenance.get("static_coverage")
        if coverage is not None:
            if not isinstance(coverage, dict):
                raise ValueError("BUNDLE_PROVENANCE_INVALID")
            coverage_ref = StoredDataRef.model_validate(coverage.get("ref"))
            self._require_scope(coverage_ref)
            expected_sources["static_coverage"] = coverage_ref
        if (
            provenance.get("scope_status") != scope_status
            or not isinstance(sources, dict)
            or set(sources) != set(expected_sources)
        ):
            raise ValueError("BUNDLE_PROVENANCE_STALE")
        for name, expected in expected_sources.items():
            if StoredDataRef.model_validate(sources[name]) != expected:
                raise ValueError("BUNDLE_SOURCE_REF_MISMATCH")
        for name in ("report_en.md", "report_kr.md"):
            body, _ = read_bundle_file(manifest, name, bounded)
            if public_projection(body) != body:
                raise ValueError("BUNDLE_PUBLIC_REPORT_RESTRICTED")
        archive = read_bundle_archive(
            manifest,
            report.bundle_archive_ref,
            lambda ref: self.read_bounded(ref, MAX_BUNDLE_ARCHIVE_BYTES),
        )
        path = bundle_dir / "bundle.zip"
        if path.resolve(strict=True) != path:
            raise ValueError("BUNDLE_PATH_UNSAFE")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > MAX_BUNDLE_ARCHIVE_BYTES
        ):
            raise ValueError("BUNDLE_PATH_UNSAFE")
        with path.open("rb") as stream:
            current = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (
                current.st_dev,
                current.st_ino,
            ) or current.st_size > MAX_BUNDLE_ARCHIVE_BYTES:
                raise ValueError("BUNDLE_PATH_CHANGED")
            disk = stream.read(MAX_BUNDLE_ARCHIVE_BYTES + 1)
        if disk != archive:
            raise ValueError("BUNDLE_ARCHIVE_CHANGED")
        return manifest, archive

    def published_report_coverage(
        self, report: StageCheckpoint, finding_ref: StoredDataRef
    ) -> tuple[StoredDataRef | None, str | None]:
        """Read the coverage claimed by an existing, exact report manifest."""

        if report.bundle_manifest_ref is None:
            raise ValueError("REPORT_BUNDLE_MANIFEST_MISSING")
        manifest = parse_bundle_manifest(
            self.read_bounded(report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES),
            finding_ref=finding_ref,
        )
        raw, _ = read_bundle_file(
            manifest,
            "evidence/provenance.json",
            lambda ref: self.read_bounded(ref, MAX_BUNDLE_FILE_BYTES),
        )
        provenance = json.loads(raw)
        if not isinstance(provenance, dict):
            raise ValueError("REPORT_BUNDLE_PROVENANCE_INVALID")
        coverage = provenance.get("static_coverage")
        if coverage is None:
            return None, None
        if not isinstance(coverage, dict) or coverage.get("disposition") not in {
            "FULL",
            "PARTIAL",
        }:
            raise ValueError("REPORT_BUNDLE_COVERAGE_INVALID")
        try:
            ref = StoredDataRef.model_validate(coverage["ref"])
        except (KeyError, ValueError) as error:
            raise ValueError("REPORT_BUNDLE_COVERAGE_INVALID") from error
        self._require_scope(ref)
        return ref, str(coverage["disposition"])

    def published_report_display_id(
        self, report: StageCheckpoint, finding_ref: StoredDataRef
    ) -> str:
        """Resolve the exact display ID claimed by a report's CAS manifest."""

        if report.bundle_manifest_ref is None:
            raise ValueError("REPORT_BUNDLE_MANIFEST_MISSING")
        manifest = parse_bundle_manifest(
            self.read_bounded(report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES),
            finding_ref=finding_ref,
        )
        return manifest.display_id

    def require_current_report_coverage(
        self,
        report: StageCheckpoint,
        finding_ref: StoredDataRef,
        current_ref: StoredDataRef | None,
        current_disposition: str,
    ) -> None:
        """Do not expose a completed report for superseded static coverage."""

        if current_ref is None:
            return
        if report.bundle_manifest_ref is None:
            raise ValueError("REPORT_STATIC_COVERAGE_STALE")
        recorded_ref, recorded_disposition = self.published_report_coverage(
            report, finding_ref
        )
        if recorded_ref != current_ref or recorded_disposition != current_disposition:
            raise ValueError("REPORT_STATIC_COVERAGE_STALE")

    def _verified_report_directory(
        self, report: StageCheckpoint, manifest: ReportBundleManifest
    ) -> Path:
        if report.bundle_manifest_ref is None or report.markdown_path is None:
            raise ValueError("BUNDLE_CURRENT_PATH_MISSING")
        expected_parent = (
            self.data_dir.resolve() / "reports" / self.identity.analysis_id
        )
        path = Path(report.markdown_path)
        allowed_names = {
            f"{manifest.display_id}.md",
            f"{manifest.display_id}-{report.bundle_manifest_ref.content_hash}.md",
        }
        if path.parent != expected_parent or path.name not in allowed_names:
            raise ValueError("BUNDLE_PATH_UNSAFE")
        bundle_dir = path.with_suffix("")
        manifest_path = bundle_dir / "manifest.json"
        if manifest_path.resolve(strict=True) != manifest_path:
            raise ValueError("BUNDLE_PATH_UNSAFE")
        info = manifest_path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or info.st_size > MAX_BUNDLE_MANIFEST_BYTES
        ):
            raise ValueError("BUNDLE_PATH_UNSAFE")
        with manifest_path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("BUNDLE_PATH_CHANGED")
            disk = stream.read(MAX_BUNDLE_MANIFEST_BYTES + 1)
        if disk != self.read_bounded(
            report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES
        ):
            raise ValueError("BUNDLE_MANIFEST_CHANGED")
        return bundle_dir

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
            if not items:
                try:
                    first = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    first = None
                if (
                    isinstance(first, dict)
                    and first.get("kind") == "simple_hypothesis_proposal"
                ):
                    self._require_proposal_original(first, raw)
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
