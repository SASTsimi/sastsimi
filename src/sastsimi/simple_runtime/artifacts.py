from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Mapping
from contextlib import closing
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.prompt_redaction import (
    contains_local_file_url,
    redact_projected_json,
    redact_untrusted_text,
    sandbox_file_urls_only,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.bilingual_bundle import is_safe_sandbox_shell_poc
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_ARCHIVE_BYTES,
    MAX_BUNDLE_FILE_BYTES,
    MAX_BUNDLE_MANIFEST_BYTES,
    ReportBundleManifest,
    parse_bundle_manifest,
    read_bundle_archive,
    read_bundle_file,
)
from sastsimi.reporting.safe_windows_directory import windows_extended_path
from sastsimi.storage.artifact_store import LocalArtifactStore

from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from .poc_currentness import poc_source_current

_MAX_CONTEXT_BYTES = 256 * 1024
_INITIAL_ENVIRONMENT_BLOCK_KIND = "simple_initial_environment_block_v1"
_PINNED_BINARY_DISTRIBUTION_UNAVAILABLE = "PINNED_BINARY_DISTRIBUTION_UNAVAILABLE"
_PINNED_REQUIREMENT_PROVENANCE_KIND = "simple_pinned_requirement_provenance_v1"
_PINNED_REQUIREMENT_PROVENANCE_SOURCES = frozenset(
    {"TARGET_MANIFEST", "DOCKERFILE_LITERAL_PIP_REQUIREMENTS"}
)
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_PINNED_DISTRIBUTION_UNAVAILABLE = re.compile(
    rb"No matching distribution found for\s+"
    rb"(?P<name>[A-Za-z0-9][A-Za-z0-9_.+\-\[\]]{0,127})"
    rb"\s*==\s*"
    rb"(?P<version>[A-Za-z0-9][A-Za-z0-9_.+\-!]{0,127})",
    re.IGNORECASE,
)

# Exact pre-origin provider fallback decisions; they were never Agent STOPs.
LEGACY_RECOVERY_FALLBACK_STOPS = frozenset(
    {
        (
            "recovery provider did not return a decision",
            "preserve the failure for manual review",
        ),
        (
            "recovery output failed policy validation",
            "preserve the failure for manual review",
        ),
    }
)


class SimpleArtifactRepository:
    """Exact record reader plus content-addressed output writer."""

    def __init__(
        self,
        data_dir: str | Path,
        identity: CheckpointIdentity,
        *,
        create_dirs: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.identity = identity
        self.paths = RuntimePaths(self.data_dir)
        self.artifacts = LocalArtifactStore(
            self.paths.artifacts,
            WorkspaceId(identity.workspace_id),
            CommitId(identity.commit_id),
            create_dirs=create_dirs,
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

    def build_initial_environment_block(
        self,
        checkpoint: StageCheckpoint,
        *,
        initial_verification_ref: StoredDataRef,
        dependency_bundle_attempt_ref: StoredDataRef,
    ) -> StoredDataRef | None:
        """Record only a deterministic, receipt-backed initial environment block.

        This intentionally derives a runtime record from the original Agent result
        and the Docker resolver receipt.  It never edits or synthesizes the Agent
        result itself.
        """

        if (
            self._verified_pinned_binary_environment_block(
                checkpoint,
                initial_verification_ref=initial_verification_ref,
                dependency_bundle_attempt_ref=dependency_bundle_attempt_ref,
            )
            is None
        ):
            return None
        return self.put_json(
            {
                "kind": _INITIAL_ENVIRONMENT_BLOCK_KIND,
                "identity": checkpoint.identity.model_dump(mode="json"),
                "attempt_id": checkpoint.attempt_id,
                "classification": _PINNED_BINARY_DISTRIBUTION_UNAVAILABLE,
                "initial_verification_ref": initial_verification_ref.model_dump(
                    mode="json"
                ),
                "dependency_bundle_attempt_ref": (
                    dependency_bundle_attempt_ref.model_dump(mode="json")
                ),
            }
        )

    def build_initial_environment_block_from_attempt_refs(
        self,
        checkpoint: StageCheckpoint,
        *,
        initial_verification_ref: StoredDataRef,
        attempt_refs: tuple[StoredDataRef, ...],
    ) -> StoredDataRef | None:
        """Use only the final matching immutable resolver receipt, if present."""

        for attempt_ref in reversed(attempt_refs):
            block_ref = self.build_initial_environment_block(
                checkpoint,
                initial_verification_ref=initial_verification_ref,
                dependency_bundle_attempt_ref=attempt_ref,
            )
            if block_ref is not None:
                return block_ref
        return None

    def build_initial_environment_block_from_checkpoint(
        self, checkpoint: StageCheckpoint
    ) -> StoredDataRef | None:
        """Recover only evidence already attached to this failed initial stage."""

        if (
            checkpoint.identity != self.identity
            or checkpoint.stage is not SimpleStage.VERIFICATION_INITIAL_DONE
            or checkpoint.attempt_id is None
        ):
            return None
        for initial_ref in checkpoint.output_refs:
            block_ref = self.build_initial_environment_block_from_attempt_refs(
                checkpoint,
                initial_verification_ref=initial_ref,
                attempt_refs=checkpoint.output_refs,
            )
            if block_ref is not None:
                return block_ref
        return None

    def verified_terminal_initial_outcome(
        self, checkpoint: StageCheckpoint | None
    ) -> Literal["INCONCLUSIVE"] | None:
        """Verify the exact Agent evidence before accepting an early HOLD."""

        if terminal_initial_outcome(checkpoint) is None:
            return None
        assert checkpoint is not None
        if (
            checkpoint.identity != self.identity
            or checkpoint.stage_version
            != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
        ):
            raise ValueError("INITIAL_VERIFICATION_EVIDENCE_INVALID")
        if checkpoint.external_prerequisites_ref is None:
            return self._verified_initial_environment_block(checkpoint)
        ref = checkpoint.external_prerequisites_ref
        try:
            payload = json.loads(self.read_bounded(ref, 1024 * 1024))
            result = payload.get("result") if isinstance(payload, dict) else None
            prerequisites = (
                result.get("unmet_external_prerequisites")
                if isinstance(result, dict)
                else None
            )
            if (
                not isinstance(payload, dict)
                or payload.get("kind") != "simple_initial_verification"
                or payload.get("attempt_id") != checkpoint.attempt_id
                or not isinstance(prerequisites, list)
                or not prerequisites
                or any(
                    not isinstance(item, str) or not item.strip()
                    for item in prerequisites
                )
            ):
                raise ValueError("INITIAL_VERIFICATION_EVIDENCE_INVALID")
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            raise ValueError("INITIAL_VERIFICATION_EVIDENCE_INVALID") from error
        return "INCONCLUSIVE"

    def _verified_initial_environment_block(
        self, checkpoint: StageCheckpoint
    ) -> Literal["INCONCLUSIVE"]:
        """Accept a HOLD only when its system receipt proves this exact block."""

        ref = checkpoint.environment_block_ref
        assert ref is not None
        try:
            payload = json.loads(self.read_bounded(ref, 1024 * 1024))
            initial_ref = StoredDataRef.model_validate(
                payload.get("initial_verification_ref")
                if isinstance(payload, dict)
                else None
            )
            receipt_ref = StoredDataRef.model_validate(
                payload.get("dependency_bundle_attempt_ref")
                if isinstance(payload, dict)
                else None
            )
            if (
                not isinstance(payload, dict)
                or payload.get("kind") != _INITIAL_ENVIRONMENT_BLOCK_KIND
                or payload.get("identity")
                != checkpoint.identity.model_dump(mode="json")
                or payload.get("attempt_id") != checkpoint.attempt_id
                or payload.get("classification")
                != _PINNED_BINARY_DISTRIBUTION_UNAVAILABLE
                or initial_ref not in checkpoint.output_refs
                or receipt_ref not in checkpoint.output_refs
                or self._verified_pinned_binary_environment_block(
                    checkpoint,
                    initial_verification_ref=initial_ref,
                    dependency_bundle_attempt_ref=receipt_ref,
                )
                is None
            ):
                raise ValueError("INITIAL_VERIFICATION_EVIDENCE_INVALID")
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            raise ValueError("INITIAL_VERIFICATION_EVIDENCE_INVALID") from error
        return "INCONCLUSIVE"

    def _verified_pinned_binary_environment_block(
        self,
        checkpoint: StageCheckpoint,
        *,
        initial_verification_ref: StoredDataRef,
        dependency_bundle_attempt_ref: StoredDataRef,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Return linked immutable evidence for one non-retryable resolver failure."""

        if (
            checkpoint.identity != self.identity
            or checkpoint.stage is not SimpleStage.VERIFICATION_INITIAL_DONE
            or checkpoint.stage_version
            != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
            or checkpoint.attempt_id is None
        ):
            return None
        try:
            initial = json.loads(
                self.read_bounded(initial_verification_ref, 1024 * 1024)
            )
            receipt = json.loads(
                self.read_bounded(dependency_bundle_attempt_ref, 256 * 1024)
            )
            if not isinstance(initial, dict) or not isinstance(receipt, dict):
                return None
            result = initial.get("result")
            stderr_ref = StoredDataRef.model_validate(receipt.get("stderr_ref"))
            stderr = self.read_bounded(stderr_ref, 256 * 1024)
        except (OSError, ValueError, TypeError, UnicodeError):
            return None
        if (
            initial.get("kind") != "simple_initial_verification"
            or initial.get("attempt_id") != checkpoint.attempt_id
            or not isinstance(result, dict)
            or result.get("initial_assessment") not in {"TRUE", "HOLD"}
            or result.get("unmet_external_prerequisites") != []
            or receipt.get("kind") != "simple_dependency_bundle_attempt"
            or receipt.get("identity") != checkpoint.identity.model_dump(mode="json")
            or receipt.get("attempt_id") != checkpoint.attempt_id
            or receipt.get("status") != "FAILED"
            or receipt.get("dependency_bundle_source") != "AUTO_RESOLVED"
            or receipt.get("error_code") != "POC_AUTO_BUNDLE_DOWNLOAD_FAILED"
            or receipt.get("timed_out") is not False
            or not self._has_verified_pinned_requirement_origin(receipt, stderr)
        ):
            return None
        return initial, receipt

    @staticmethod
    def _has_verified_pinned_requirement_origin(
        receipt: Mapping[str, Any], stderr: bytes
    ) -> bool:
        """Prove the unavailable exact pin came from a repository input.

        The resolver's stderr alone proves only that *some* requested package
        was unavailable.  A terminal result is safe only when the immutable
        receipt also binds that exact pin to the selected target manifest or
        literal Dockerfile input, before any Agent-provided extras were added.
        """

        match = _PINNED_DISTRIBUTION_UNAVAILABLE.search(stderr)
        provenance = receipt.get("pinned_requirement_provenance")
        manifest_sha256 = receipt.get("manifest_sha256")
        if (
            match is None
            or not isinstance(provenance, dict)
            or set(provenance)
            != {
                "kind",
                "source_kind",
                "source_path",
                "source_sha256",
                "requirements",
            }
            or provenance.get("kind") != _PINNED_REQUIREMENT_PROVENANCE_KIND
            or provenance.get("source_kind")
            not in _PINNED_REQUIREMENT_PROVENANCE_SOURCES
            or provenance.get("source_kind")
            != receipt.get("dependency_resolution_input_kind")
            or not isinstance(manifest_sha256, str)
            or _SHA256_HEX.fullmatch(manifest_sha256) is None
            or provenance.get("source_sha256") != manifest_sha256
        ):
            return False
        source_path = provenance.get("source_path")
        source_kind = provenance["source_kind"]
        if not isinstance(source_path, str):
            return False
        if source_kind == "TARGET_MANIFEST":
            if (
                not source_path.endswith(("requirements.txt", "pyproject.toml"))
                or source_path.startswith(("/", "\\"))
                or "\\" in source_path
            ):
                return False
        elif source_path != "Dockerfile":
            return False
        requirements = provenance.get("requirements")
        if (
            not isinstance(requirements, list)
            or not requirements
            or len(requirements) > 10_000
            or any(
                not isinstance(item, str) or not item or len(item) > 4_096
                for item in requirements
            )
        ):
            return False
        try:
            missing = Requirement(
                "{}=={}".format(
                    match.group("name").decode("ascii"),
                    match.group("version").decode("ascii"),
                )
            )
            expected_specifier = str(missing.specifier)
            if missing.url is not None or expected_specifier.count("==") != 1:
                return False
            for raw in requirements:
                candidate = Requirement(raw)
                if candidate.url is not None:
                    return False
                if (
                    canonicalize_name(candidate.name) == canonicalize_name(missing.name)
                    and str(candidate.specifier) == expected_specifier
                    # The resolver image's marker environment is not present
                    # in this receipt. A conditional pin proves no active pin.
                    and candidate.marker is None
                ):
                    return True
        except (InvalidRequirement, UnicodeDecodeError):
            return False
        return False

    def verified_terminal_poc_outcome(
        self, checkpoint: StageCheckpoint | None
    ) -> Literal["INCONCLUSIVE"] | None:
        """Fail closed if an inconclusive terminal PoC loses its exact evidence."""

        if checkpoint is None:
            return None
        if checkpoint.poc_stop_decision_ref is None:
            if terminal_poc_outcome(checkpoint) is None:
                return None
            self._verified_poc_observation(checkpoint)
            return "INCONCLUSIVE"
        if (
            terminal_poc_outcome(checkpoint) is None
            or checkpoint.identity != self.identity
        ):
            raise ValueError("POC_STOP_EVIDENCE_INVALID")
        if checkpoint.attempt_id is None or len(checkpoint.output_refs) != 2:
            raise ValueError("POC_STOP_EVIDENCE_INVALID")
        execution_ref, interpretation_ref = checkpoint.output_refs
        try:
            decision = json.loads(
                self.read_bounded(checkpoint.poc_stop_decision_ref, 1024 * 1024)
            )
            execution = json.loads(self.read(execution_ref))
            interpretation = json.loads(self.read(interpretation_ref))
            original_error = (
                decision.get("original_error") if isinstance(decision, dict) else None
            )
            stop = decision.get("decision") if isinstance(decision, dict) else None
            result = (
                interpretation.get("result")
                if isinstance(interpretation, dict)
                else None
            )
            if (
                not isinstance(decision, dict)
                or not isinstance(original_error, dict)
                or not isinstance(stop, dict)
                or not isinstance(execution, dict)
                or not isinstance(interpretation, dict)
                or decision.get("kind") != "simple_recovery_decision"
                or decision.get("identity")
                != checkpoint.identity.model_dump(mode="json")
                or decision.get("stage") != checkpoint.stage.value
                or decision.get("attempt") != checkpoint.attempt_number
                or decision.get("attempt_id") != checkpoint.attempt_id
                or decision.get("decision_origin") not in {None, "AGENT"}
                or decision.get("decision_origin") is None
                and (
                    "decision_origin" in decision
                    or (stop.get("diagnosis"), stop.get("guidance"))
                    in LEGACY_RECOVERY_FALLBACK_STOPS
                )
                or original_error.get("code") != "POC_INCONCLUSIVE"
                or original_error.get("retryable") is not True
                or not isinstance(original_error.get("safe_message"), str)
                or original_error.get("invalid_field") is not None
                and not isinstance(original_error.get("invalid_field"), str)
                or original_error.get("evidence_refs")
                != [ref.model_dump(mode="json") for ref in checkpoint.output_refs]
                or stop.get("action") != "STOP"
                or stop.get("category")
                not in {
                    "TRANSIENT_TOOL",
                    "GENERATED_INPUT",
                    "ENVIRONMENT",
                    "TERMINAL",
                }
                or not isinstance(stop.get("diagnosis"), str)
                or not isinstance(stop.get("guidance"), str)
                or stop.get("environment_patch") != ""
                or execution.get("kind") != "simple_poc_execution"
                or execution.get("attempt_id") != checkpoint.attempt_id
                or checkpoint.container_id is not None
                and execution.get("container_id") != checkpoint.container_id
                or execution.get("timed_out") is not False
                or type(execution.get("exit_code")) is not int
                or execution.get("exit_code") != 0
                or interpretation.get("kind") != "simple_dynamic_interpretation"
                or interpretation.get("execution_ref")
                != execution_ref.model_dump(mode="json")
                or not isinstance(result, dict)
                or result.get("outcome") != "INCONCLUSIVE"
            ):
                raise ValueError("POC_STOP_EVIDENCE_INVALID")
            with closing(
                sqlite3.connect(
                    f"file:{self.paths.database.as_posix()}?mode=ro", uri=True
                )
            ) as connection:
                rows = connection.execute(
                    "SELECT event_json FROM agent_activity_events "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND attempt_id = ?",
                    (
                        checkpoint.identity.analysis_id,
                        checkpoint.identity.hypothesis_id or "",
                        checkpoint.attempt_id,
                    ),
                ).fetchall()
            if not any(
                self._matches_poc_stop_event(
                    row[0], checkpoint, checkpoint.poc_stop_decision_ref
                )
                for row in rows
            ):
                raise ValueError("POC_STOP_EVIDENCE_INVALID")
        except (OSError, ValueError, TypeError, UnicodeError, sqlite3.Error) as error:
            raise ValueError("POC_STOP_EVIDENCE_INVALID") from error
        return "INCONCLUSIVE"

    def _verified_poc_observation(self, checkpoint: StageCheckpoint) -> None:
        if (
            checkpoint.identity != self.identity
            or checkpoint.attempt_id is None
            or len(checkpoint.output_refs) not in {2, 3}
        ):
            raise ValueError("POC_TERMINAL_EVIDENCE_INVALID")
        execution_ref, interpretation_ref = checkpoint.output_refs[:2]
        try:
            execution = json.loads(self.read(execution_ref))
            interpretation = json.loads(self.read(interpretation_ref))
            cleanup = (
                json.loads(self.read(checkpoint.output_refs[2]))
                if len(checkpoint.output_refs) == 3
                else None
            )
            result = (
                interpretation.get("result")
                if isinstance(interpretation, dict)
                else None
            )
            if (
                not isinstance(execution, dict)
                or not isinstance(interpretation, dict)
                or execution.get("kind") != "simple_poc_execution"
                or execution.get("attempt_id") != checkpoint.attempt_id
                or checkpoint.container_id is not None
                and execution.get("container_id") != checkpoint.container_id
                or execution.get("timed_out") is not False
                or type(execution.get("exit_code")) is not int
                or execution.get("exit_code") != 0
                or interpretation.get("kind") != "simple_dynamic_interpretation"
                or interpretation.get("execution_ref")
                != execution_ref.model_dump(mode="json")
                or not isinstance(result, dict)
                or result.get("outcome") != "INCONCLUSIVE"
                or len(checkpoint.output_refs) == 3
                and (
                    not isinstance(cleanup, dict)
                    or cleanup.get("kind") != "simple_container_cleanup"
                    or cleanup.get("attempt_id") != checkpoint.attempt_id
                    or cleanup.get("container_id") != checkpoint.container_id
                    or cleanup.get("status") != "REMOVED"
                )
            ):
                raise ValueError("POC_TERMINAL_EVIDENCE_INVALID")
        except (OSError, ValueError, TypeError, UnicodeError, sqlite3.Error) as error:
            raise ValueError("POC_TERMINAL_EVIDENCE_INVALID") from error

    @staticmethod
    def _matches_poc_stop_event(
        raw: str, checkpoint: StageCheckpoint, decision_ref: StoredDataRef
    ) -> bool:
        try:
            event = AgentActivityEvent.model_validate_json(raw)
        except (ValueError, TypeError):
            return False
        return (
            event.kind is ActivityKind.DECISION_RECORDED
            and event.stage == checkpoint.stage.value
            and event.analysis_id == checkpoint.identity.analysis_id
            and event.workspace_id == checkpoint.identity.workspace_id
            and event.commit_id == checkpoint.identity.commit_id
            and event.hypothesis_id == checkpoint.identity.hypothesis_id
            and event.attempt_id == checkpoint.attempt_id
            and event.error_code == "POC_INCONCLUSIVE"
            and event.output_refs == (decision_ref,)
        )

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
        if not poc_source_current(candidate, read_content=self.read_bounded):
            raise ValueError("BUNDLE_POC_SOURCE_UNVERIFIED")
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
        for entry in manifest.files:
            body, _ = read_bundle_file(manifest, entry.path, bounded)
            if contains_local_file_url(body) and not (
                sandbox_file_urls_only(body)
                and (
                    (entry.path == "poc.sh" and is_safe_sandbox_shell_poc(body))
                    or entry.path
                    in {
                        "evidence/stdout.txt",
                        "evidence/stderr.txt",
                        "evidence/provenance.json",
                    }
                )
            ):
                raise ValueError("BUNDLE_LOCAL_FILE_URL")
            if entry.path in {"report_en.md", "report_kr.md"}:
                if public_projection(body) != body:
                    raise ValueError("BUNDLE_PUBLIC_REPORT_RESTRICTED")
        archive = read_bundle_archive(
            manifest,
            report.bundle_archive_ref,
            lambda ref: self.read_bounded(ref, MAX_BUNDLE_ARCHIVE_BYTES),
        )
        path = windows_extended_path(bundle_dir / "bundle.zip")
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
        manifest_path = windows_extended_path(bundle_dir / "manifest.json")
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

    def prompt_context_prioritized(
        self,
        required_refs: tuple[StoredDataRef, ...],
        optional_refs: tuple[StoredDataRef, ...],
        *,
        max_bytes: int = _MAX_CONTEXT_BYTES,
    ) -> bytes:
        """Keep each required CAS object whole and identify omitted optional refs."""

        items: list[dict[str, Any]] = []
        required = tuple(dict.fromkeys(required_refs))
        optional = tuple(
            ref for ref in dict.fromkeys(optional_refs) if ref not in required
        )

        def item_for(ref: StoredDataRef) -> dict[str, Any]:
            raw = self.read(ref)
            if not items:
                try:
                    proposal = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    proposal = None
                if (
                    isinstance(proposal, dict)
                    and proposal.get("kind") == "simple_hypothesis_proposal"
                ):
                    self._require_proposal_original(proposal, raw)
            redacted = self._redacted(raw)
            if not items and redacted != raw:
                raise ValueError("SIMPLE_RUNTIME_CONTEXT_REDACTED")
            payload = raw if not items else redacted
            try:
                data: Any = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = payload.decode("utf-8", errors="strict")
            return {"reference": ref.model_dump(mode="json"), "data": data}

        for ref in required:
            items.append(item_for(ref))
            if len(canonical_bytes({"exact_inputs": items})) > max_bytes:
                raise ValueError("SIMPLE_RUNTIME_CONTEXT_TOO_LARGE")

        omitted = 0
        for ref in optional:
            try:
                item = item_for(ref)
            except (OSError, ValueError, UnicodeError, sqlite3.Error):
                omitted += 1
                continue
            proposed = canonical_bytes(
                {"exact_inputs": [*items, item], "omitted_optional_refs": omitted}
            )
            if len(proposed) > max_bytes:
                omitted += 1
            else:
                items.append(item)
        result = canonical_bytes(
            {"exact_inputs": items, "omitted_optional_refs": omitted}
        )
        if len(result) > max_bytes:
            raise ValueError("SIMPLE_RUNTIME_CONTEXT_TOO_LARGE")
        return result

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


def verified_terminal_projection(
    checkpoints: tuple[StageCheckpoint, ...], data_dir: str | Path | None
) -> tuple[StageCheckpoint, ...]:
    """Fail closed in read-only status views when terminal evidence is lost."""

    projected: list[StageCheckpoint] = []
    for checkpoint in checkpoints:
        initial = terminal_initial_outcome(checkpoint) is not None
        terminal_poc = (
            checkpoint.poc_stop_decision_ref is not None
            or terminal_poc_outcome(checkpoint) is not None
        )
        if not initial and not terminal_poc:
            projected.append(checkpoint)
            continue
        error_code = (
            "INITIAL_VERIFICATION_EVIDENCE_INVALID"
            if initial
            else "POC_STOP_EVIDENCE_INVALID"
            if checkpoint.poc_stop_decision_ref is not None
            else "POC_TERMINAL_EVIDENCE_INVALID"
        )
        try:
            if data_dir is None:
                raise ValueError(error_code)
            artifacts = SimpleArtifactRepository(
                data_dir, checkpoint.identity, create_dirs=False
            )
            if initial:
                artifacts.verified_terminal_initial_outcome(checkpoint)
            else:
                artifacts.verified_terminal_poc_outcome(checkpoint)
        except (OSError, ValueError, sqlite3.Error):
            projected.append(
                checkpoint.model_copy(
                    update={
                        "status": StageStatus.BLOCKED,
                        "error_code": error_code,
                        "retryable": False,
                    }
                )
            )
        else:
            projected.append(checkpoint)
    return tuple(projected)


__all__ = ["SimpleArtifactRepository", "verified_terminal_projection"]
