"""Application service for new and resumed local repository analyses."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import uuid4

from pydantic import Field

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_projected_json
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore

from .artifacts import SimpleArtifactRepository
from .ast_facts import focus_ast_facts, index_ast_manifest, validate_ast_manifest
from .attack_surfaces import (
    SurfaceCoverage,
    SurfaceIndex,
    SurfaceReview,
    build_attack_surface_index,
    candidate_inventory_hash,
    evaluate_surface_coverage,
    surface_index_from_json,
)
from .call_queue import effective_hypothesis_concurrency
from .candidate_batches import (
    MAX_CANDIDATES_PER_BATCH,
    CandidateBatch,
    iter_candidate_batches,
)
from .candidates import StaticCandidate, ingest_static_candidates
from .chaining import (
    ChainingPoolBatch,
    SimpleChainingStage,
    validated_chaining_children,
)
from .discovery import BUDGET_PAUSE_CODES, CandidateDiscovery
from .models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
    terminal_gate_outcome,
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from .provider import SimpleLLMClient
from .recovery import (
    MAX_RECOVERY_ATTEMPTS,
    RecoveryAction,
    RecoveryCoordinator,
)
from .run_lease import AnalysisRunBusy, analysis_run_lease
from .runner import RunOutcome, SimpleRuntimeRunner, StageBlocked, StageFailed
from .stages import ProConEvidenceRefInvalid, ProConStage
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_contexts import (
    SurfaceContext,
    SurfaceContextOverflow,
    expanded_surface_contexts,
    iter_uncovered_surface_contexts,
)


class SimpleAnalysisRequest(ContractModel):
    data_dir: Path
    repository: str
    commit: str


class StaticBootstrapResult(ContractModel):
    repository_profile_ref: StoredDataRef
    static_bundle_ref: StoredDataRef
    workspace_path: Path
    static_coverage_ref: StoredDataRef | None = None
    static_disposition: Literal["FULL", "PARTIAL"] = "FULL"
    security_policy_ref: StoredDataRef | None = None
    policy_snapshot_ref: StoredDataRef | None = None


class StaticEvidenceInvalid(ValueError):
    retryable = False

    def __init__(self) -> None:
        super().__init__("STATIC_EVIDENCE_INVALID")


class ChainingEvidenceInvalid(ValueError):
    def __init__(self, checkpoint: StageCheckpoint) -> None:
        self.checkpoint = checkpoint
        super().__init__("CHAINING_EVIDENCE_INVALID")


class HypothesisSeed(ContractModel):
    hypothesis_id: str
    proposal_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class CandidateProposalOutcome:
    status: str
    reason: str
    seeds: tuple[HypothesisSeed, ...]
    result_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class BatchProposalResult:
    results: dict[str, CandidateProposalOutcome]
    missing_ids: tuple[str, ...]
    attempt_refs: tuple[StoredDataRef, ...]
    failure: StageFailure | None = None


class SimpleAnalysisOutcome(ContractModel):
    identity: CheckpointIdentity
    display_analysis_id: str
    status: Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE", "PARTIAL", "PAUSED"]
    current_stage: SimpleStage
    error_code: str | None = None
    child_hypothesis_id: str | None = Field(default=None, exclude=True)
    child_attempt_id: str | None = Field(default=None, exclude=True)


class OfflineRepairPreflight(ContractModel):
    """Read-only proof that the configured, pinned offline base can run a browser."""

    base_image_digest: str
    browser_command: str
    python_version: str
    smoke_output_digest: str


class StaticBootstrap(Protocol):
    async def run(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> StaticBootstrapResult: ...


class HypothesisBootstrap(Protocol):
    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...] | StageFailure: ...


type RunnerFactory = Callable[
    [SimpleCheckpointStore, CheckpointIdentity, StaticBootstrapResult],
    SimpleRuntimeRunner,
]
type RecoveryFactory = Callable[[CheckpointIdentity], RecoveryCoordinator]


class SimpleAnalysisApplication:
    def __init__(
        self,
        *,
        data_dir: Path,
        store: SimpleCheckpointStore,
        static_bootstrap: StaticBootstrap,
        hypothesis_bootstrap: HypothesisBootstrap,
        runner_factory: RunnerFactory,
        recovery_factory: RecoveryFactory | None = None,
        id_factory: Callable[[], str] | None = None,
        profile_ref: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        llm_provider: str | None = None,
        on_demand_possible: bool = False,
        max_parallel_hypotheses: int = 1,
        max_elapsed_seconds: ElapsedLimit | None = None,
        max_tokens: TokenLimit | None = None,
        max_cost_minor_units: int | None = None,
        candidate_pipeline_enabled: bool = False,
        candidate_pipeline_version: int = 2,
        max_pending_candidate_children: int = 128,
        candidate_client_factory: Callable[
            [CheckpointIdentity, SimpleArtifactRepository], SimpleLLMClient
        ]
        | None = None,
        candidate_hypothesis_bootstrap: HypothesisBootstrap | None = None,
        offline_repair_preflight: (
            Callable[[CheckpointIdentity], Awaitable[OfflineRepairPreflight]] | None
        ) = None,
    ) -> None:
        if not 1 <= max_parallel_hypotheses <= 32:
            raise ValueError("PARALLEL_HYPOTHESIS_LIMIT_INVALID")
        if candidate_pipeline_version not in {1, 2}:
            raise ValueError("CANDIDATE_PIPELINE_VERSION_INVALID")
        if max_pending_candidate_children < MAX_CANDIDATES_PER_BATCH * 4:
            raise ValueError("CANDIDATE_PENDING_LIMIT_INVALID")
        self._data_dir = data_dir
        self._store = store
        self._static = static_bootstrap
        self._hypotheses = hypothesis_bootstrap
        self._runner_factory = runner_factory
        self._recovery_factory = recovery_factory
        self._ids = id_factory or (lambda: uuid4().hex)
        self._display = AnalysisDisplayIdStore(store.database_path)
        self._profile_ref = profile_ref
        self._provider = provider
        self._model = model
        self._llm_provider = llm_provider
        self._on_demand_possible = on_demand_possible
        self._max_parallel_hypotheses = (
            effective_hypothesis_concurrency(llm_provider, max_parallel_hypotheses)
            if llm_provider is not None
            else max_parallel_hypotheses
        )
        self._max_elapsed_seconds = max_elapsed_seconds
        self._max_tokens = max_tokens
        self._max_cost_minor_units = max_cost_minor_units
        self._candidate_pipeline_enabled = candidate_pipeline_enabled
        self._candidate_pipeline_version = candidate_pipeline_version
        self._max_pending_candidate_children = max_pending_candidate_children
        self._candidate_client_factory = candidate_client_factory
        self._candidate_hypotheses = (
            candidate_hypothesis_bootstrap or hypothesis_bootstrap
        )
        self._offline_repair_preflight = offline_repair_preflight

    async def analyze(
        self,
        request: SimpleAnalysisRequest,
        *,
        on_analysis_started: Callable[[str], None] | None = None,
    ) -> SimpleAnalysisOutcome:
        analysis_id = self._ids()
        workspace_id = self._ids()
        display_id = self._display.get_or_allocate(analysis_id)
        identity = CheckpointIdentity(
            analysis_id=analysis_id,
            workspace_id=workspace_id,
            commit_id=request.commit.lower(),
            hypothesis_id=None,
        )
        run = SimpleAnalysisRun(
            analysis_id=analysis_id,
            display_analysis_id=display_id,
            workspace_id=workspace_id,
            commit_id=request.commit.lower(),
            repository=request.repository,
            profile_ref=self._profile_ref,
            provider=self._provider,
            model=self._model,
            started_at=datetime.now(UTC),
            llm_provider=self._llm_provider,
            on_demand_possible=self._on_demand_possible,
            candidate_pipeline_version=(
                self._candidate_pipeline_version
                if self._candidate_pipeline_enabled
                else None
            ),
        )
        with analysis_run_lease(self._data_dir, analysis_id):
            self._store.save_analysis_run(run)
            if on_analysis_started is not None:
                on_analysis_started(analysis_id)
            return await self._run_static(run, identity)

    async def _run_static(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
    ) -> SimpleAnalysisOutcome:
        if (
            run.candidate_pipeline_version in {1, 2}
            and run.candidate_terminal is not None
        ):
            run = run.model_copy(update={"candidate_terminal": None})
            self._store.save_analysis_run(run)
        while True:
            should_retry, terminal = await self._resume_bootstrap_failure(
                identity,
                SimpleStage.STATIC_DONE,
            )
            if should_retry:
                continue
            if terminal is not None:
                return self._bootstrap_outcome(run, terminal)
            checkpoint = self._store.mark_running(
                identity,
                SimpleStage.STATIC_DONE,
                self._store.input_refs_for(identity, SimpleStage.STATIC_DONE),
                attempt_id=uuid4().hex,
            )
            try:
                static = await self._static.run(
                    SimpleAnalysisRequest(
                        data_dir=self._data_dir,
                        repository=run.repository,
                        commit=run.commit_id,
                    ),
                    identity,
                )
                self._validate_static_evidence(static, identity)
                refresh_hypotheses = False
                if run.static_disposition == "PARTIAL" and run.hypothesis_ids:
                    previous_agent_ref = self._hypothesis_static_ref(identity)
                    if previous_agent_ref is None:
                        raise StaticEvidenceInvalid()
                    refresh_hypotheses = self._static_facts_changed(
                        identity, previous_agent_ref, static.static_bundle_ref
                    )
                    hypothesis_checkpoint = self._store.get(
                        identity, SimpleStage.HYPOTHESIS_DONE
                    )
                    refresh_hypotheses = refresh_hypotheses or (
                        hypothesis_checkpoint is None
                        or hypothesis_checkpoint.status is not StageStatus.SUCCEEDED
                    )
            except Exception as error:
                coverage_ref = getattr(error, "coverage_ref", None)
                bundle_ref = getattr(error, "bundle_ref", None)
                static_evidence = tuple(
                    ref
                    for ref in (coverage_ref, bundle_ref)
                    if isinstance(ref, StoredDataRef)
                )
                has_static_evidence = bool(static_evidence)
                failure = StageFailure(
                    code=self._safe_error_code(error, "STATIC_BOOTSTRAP_BLOCKED"),
                    retryable=bool(getattr(error, "retryable", True)),
                    safe_message="Repository or static analysis did not complete",
                    evidence_refs=static_evidence,
                )
                failed = self._store.mark_failure(
                    checkpoint,
                    failure,
                    StageStatus.BLOCKED,
                )
                if not has_static_evidence and await self._prepare_bootstrap_retry(
                    failed, failure
                ):
                    continue
                return self._bootstrap_outcome(
                    run,
                    self._store.require(identity, SimpleStage.STATIC_DONE),
                )
            updated_run = run.model_copy(
                update={
                    "workspace_path": static.workspace_path,
                    "repository_profile_ref": static.repository_profile_ref,
                    "static_bundle_ref": static.static_bundle_ref,
                    "static_coverage_ref": static.static_coverage_ref,
                    "static_disposition": static.static_disposition,
                    "security_policy_ref": static.security_policy_ref,
                    "policy_snapshot_ref": static.policy_snapshot_ref,
                }
            )
            self._store.complete(
                checkpoint,
                self._stage_result(
                    static.repository_profile_ref,
                    static.static_bundle_ref,
                    *(
                        (static.policy_snapshot_ref,)
                        if static.policy_snapshot_ref is not None
                        else ()
                    ),
                ),
                analysis_run=updated_run,
            )
            break
        if updated_run.candidate_pipeline_version in {1, 2}:
            return await self._run_candidate_pipeline(updated_run, identity, static)
        if run.static_disposition == "PARTIAL" and run.hypothesis_ids:
            if refresh_hypotheses:
                try:
                    return await self._propose_and_run(
                        updated_run, identity, static, append_existing=True
                    )
                except StaticEvidenceInvalid:
                    return self._invalid_hypothesis_resume(updated_run, identity)
            return await self._run_hypotheses(updated_run, identity, static)
        return await self._propose_and_run(updated_run, identity, static)

    async def resume(
        self,
        analysis_id_or_display: str,
        *,
        repair_exhausted_hypothesis: str | None = None,
    ) -> SimpleAnalysisOutcome:
        exact = self._display.resolve(analysis_id_or_display)
        try:
            with analysis_run_lease(self._data_dir, exact):
                if repair_exhausted_hypothesis is not None:
                    await self._prepare_offline_repair_locked(
                        exact, repair_exhausted_hypothesis
                    )
                return await self._resume_locked(exact)
        except AnalysisRunBusy:
            run = self._store.require_analysis_run(exact)
            checkpoints = self._store.list_checkpoints(exact)
            current_stage = (
                max(checkpoints, key=lambda item: item.updated_at).stage
                if checkpoints
                else SimpleStage.STATIC_DONE
            )
            return SimpleAnalysisOutcome(
                identity=CheckpointIdentity(
                    analysis_id=run.analysis_id,
                    workspace_id=run.workspace_id,
                    commit_id=run.commit_id,
                    hypothesis_id=None,
                ),
                display_analysis_id=run.display_analysis_id,
                status="RUNNING",
                current_stage=current_stage,
                error_code="ANALYSIS_ALREADY_RUNNING",
            )

    async def _prepare_offline_repair_locked(
        self, analysis_id: str, hypothesis_id: str
    ) -> None:
        preflight_callback = self._offline_repair_preflight
        if preflight_callback is None:
            raise ValueError("OFFLINE_REPAIR_NOT_CONFIGURED")
        run = self._store.require_analysis_run(analysis_id)
        root_identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        if not hypothesis_id or not (
            hypothesis_id in run.hypothesis_ids
            or self._store.has_hypothesis(root_identity, hypothesis_id)
        ):
            raise ValueError("OFFLINE_REPAIR_HYPOTHESIS_INVALID")
        if self._store.unresolved_codex_call(analysis_id) is not None:
            raise ValueError("OFFLINE_REPAIR_CODEX_CALL_UNRESOLVED")
        identity = root_identity.model_copy(update={"hypothesis_id": hypothesis_id})
        exhausted = self._store.get(identity, SimpleStage.POC_EXECUTION_DONE)
        if (
            exhausted is None
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.attempt_number != MAX_RECOVERY_ATTEMPTS
            or exhausted.recipe_ref is None
        ):
            raise ValueError("OFFLINE_REPAIR_EXHAUSTION_INVALID")
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            recipe = json.loads(
                artifacts.read_bounded(exhausted.recipe_ref, 256 * 1024)
            )
        except (OSError, ValueError, TypeError, sqlite3.Error) as error:
            raise ValueError("OFFLINE_REPAIR_RECIPE_INVALID") from error
        old_base = recipe.get("base_image_digest") if isinstance(recipe, dict) else None
        digest_pattern = r"sha256:[0-9a-f]{64}"
        if (
            not isinstance(recipe, dict)
            or recipe.get("kind") != "simple_environment_recipe"
            or not isinstance(old_base, str)
            or re.fullmatch(digest_pattern, old_base) is None
        ):
            raise ValueError("OFFLINE_REPAIR_RECIPE_INVALID")
        try:
            preflight = OfflineRepairPreflight.model_validate(
                await preflight_callback(identity)
            )
        except (OSError, ValueError) as error:
            raise ValueError("OFFLINE_REPAIR_PREFLIGHT_FAILED") from error
        if (
            re.fullmatch(digest_pattern, preflight.base_image_digest) is None
            or preflight.base_image_digest == old_base
            or not preflight.browser_command.startswith("/")
            or re.fullmatch(r"3\.12\.\d+", preflight.python_version) is None
            or re.fullmatch(digest_pattern, preflight.smoke_output_digest) is None
        ):
            raise ValueError("OFFLINE_REPAIR_PREFLIGHT_INVALID")
        proof_ref = artifacts.put_json(
            {
                "kind": "simple_offline_environment_repair",
                "identity": identity.model_dump(mode="json"),
                "stage": SimpleStage.POC_EXECUTION_DONE.value,
                "exhausted_attempt_id": exhausted.attempt_id,
                "exhausted_attempt_number": exhausted.attempt_number,
                "exhausted_checkpoint_hash": hashlib.sha256(
                    canonical_bytes(exhausted.model_dump(mode="json"))
                ).hexdigest(),
                "old_base_image_digest": old_base,
                "new_base_image_digest": preflight.base_image_digest,
                "browser_command": preflight.browser_command,
                "python_version": preflight.python_version,
                "smoke_output_digest": preflight.smoke_output_digest,
            }
        )
        self._store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)

    async def _resume_locked(self, exact: str) -> SimpleAnalysisOutcome:
        run = self._store.require_analysis_run(exact)
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        if self._store.unresolved_codex_call(exact) is not None:
            try:
                if not self._store._reconcile_unspawned_codex_call_with_lease(
                    run, self._data_dir
                ):
                    self._store._reconcile_exited_codex_call_with_lease(
                        run, self._data_dir
                    )
            except (OSError, ValueError, sqlite3.Error):
                # A missing or unverifiable process proof stays unresolved.
                pass
        checkpoints = self._store.list_checkpoints(exact)
        if self._store.unresolved_codex_call(exact) is not None:
            latest = (
                max(checkpoints, key=lambda item: item.updated_at).stage
                if checkpoints
                else SimpleStage.STATIC_DONE
            )
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=latest,
                error_code="CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            )
        root_codex_pending = next(
            (
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.identity.hypothesis_id is None
                and checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
                and checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                and (checkpoint.error_code or "").startswith(
                    "CANDIDATE_CHILD_CODEX_STATE_PENDING"
                )
            ),
            None,
        )
        marker_parts = (
            root_codex_pending.error_code.split(":", 2)
            if root_codex_pending is not None and root_codex_pending.error_code
            else []
        )
        pending_child_id = marker_parts[1] if len(marker_parts) == 3 else ""
        pending_attempt_id = marker_parts[2] if len(marker_parts) == 3 else ""
        matching_child = any(
            bool(pending_child_id)
            and bool(pending_attempt_id)
            and checkpoint.identity.hypothesis_id == pending_child_id
            and checkpoint.identity.workspace_id == identity.workspace_id
            and checkpoint.identity.commit_id == identity.commit_id
            and checkpoint.attempt_id == pending_attempt_id
            and checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and checkpoint.error_code
            in {"CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"}
            for checkpoint in checkpoints
        )
        if root_codex_pending is not None and not matching_child:
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=SimpleStage.HYPOTHESIS_DONE,
                error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            )
        for checkpoint in checkpoints:
            if (
                checkpoint.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
                and checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            ):
                try:
                    confirmed = self._store.has_codex_cleanup_confirmation(
                        checkpoint,
                        SimpleArtifactRepository(self._data_dir, checkpoint.identity),
                    )
                except (OSError, ValueError, sqlite3.Error):
                    confirmed = False
                if not confirmed:
                    return SimpleAnalysisOutcome(
                        identity=identity,
                        display_analysis_id=run.display_analysis_id,
                        status="BLOCKED",
                        current_stage=checkpoint.stage,
                        error_code=checkpoint.error_code,
                    )
        for checkpoint in checkpoints:
            if terminal_initial_outcome(checkpoint) is None:
                continue
            try:
                SimpleArtifactRepository(
                    self._data_dir, checkpoint.identity
                ).verified_terminal_initial_outcome(checkpoint)
            except (OSError, ValueError, sqlite3.Error):
                failed = self._store.mark_failure(
                    checkpoint,
                    StageFailure(
                        code="INITIAL_VERIFICATION_EVIDENCE_INVALID",
                        retryable=False,
                        safe_message=(
                            "Initial verification evidence is unavailable or invalid"
                        ),
                        evidence_refs=checkpoint.output_refs,
                    ),
                    StageStatus.BLOCKED,
                )
                return self._bootstrap_outcome(run, failed)
        for checkpoint in checkpoints:
            if (
                checkpoint.poc_stop_decision_ref is None
                and terminal_poc_outcome(checkpoint) is None
            ):
                continue
            error_code = (
                "POC_STOP_EVIDENCE_INVALID"
                if checkpoint.poc_stop_decision_ref is not None
                else "POC_TERMINAL_EVIDENCE_INVALID"
            )
            try:
                SimpleArtifactRepository(
                    self._data_dir, checkpoint.identity
                ).verified_terminal_poc_outcome(checkpoint)
            except (OSError, ValueError, sqlite3.Error):
                failed = self._store.mark_failure(
                    checkpoint,
                    StageFailure(
                        code=error_code,
                        retryable=False,
                        safe_message="Terminal PoC evidence is unavailable or invalid",
                        evidence_refs=checkpoint.output_refs,
                    ),
                    StageStatus.BLOCKED,
                )
                return self._bootstrap_outcome(run, failed)
        if run.static_bundle_ref is not None:
            await self._assert_completed_static_scope(run, identity)
            if run.static_disposition == "PARTIAL":
                if run.repository_profile_ref is None or run.workspace_path is None:
                    return self._invalid_partial_resume(run, identity)
                try:
                    self._validate_static_evidence(
                        StaticBootstrapResult(
                            repository_profile_ref=run.repository_profile_ref,
                            static_bundle_ref=run.static_bundle_ref,
                            workspace_path=run.workspace_path,
                            static_coverage_ref=run.static_coverage_ref,
                            static_disposition="PARTIAL",
                            security_policy_ref=run.security_policy_ref,
                            policy_snapshot_ref=run.policy_snapshot_ref,
                        ),
                        identity,
                    )
                except StaticEvidenceInvalid:
                    return self._invalid_partial_resume(run, identity)
            elif run.static_bundle_ref.data_kind == "artifact":
                try:
                    artifacts = SimpleArtifactRepository(self._data_dir, identity)
                    bundle = json.loads(artifacts.read(run.static_bundle_ref))
                    ast_summary = (
                        bundle.get("ast_summary") if isinstance(bundle, dict) else None
                    )
                    if isinstance(ast_summary, dict):
                        validate_ast_manifest(artifacts, ast_summary)
                except (OSError, ValueError, KeyError, TypeError):
                    return self._invalid_partial_resume(run, identity)
        if (
            run.static_coverage_ref is not None
            and run.candidate_pipeline_version not in {1, 2}
        ):
            try:
                run = self._reconcile_hypothesis_checkpoint(run, identity)
            except StaticEvidenceInvalid:
                return self._invalid_partial_resume(run, identity)
        if run.candidate_pipeline_version in {1, 2}:
            try:
                self._verify_registered_candidate_proposals(identity)
            except (OSError, ValueError, StaticEvidenceInvalid):
                return self._invalid_hypothesis_resume(run, identity)
        if run.candidate_pipeline_version in {1, 2}:
            try:
                await self._repair_invalid_saved_pro_con(exact)
            except (OSError, ValueError, StaticEvidenceInvalid):
                return self._invalid_hypothesis_resume(run, identity)
            run = self._store.require_analysis_run(exact)
        self._promote_legacy_inconclusive_pocs(exact)
        if (
            run.candidate_pipeline_version in {1, 2}
            and self._max_cost_minor_units is not None
        ):
            self._store.reopen_budget_failures(
                exact,
                max_tokens=self._max_tokens or "unlimited",
                max_cost_minor_units=self._max_cost_minor_units,
                max_elapsed_seconds=self._max_elapsed_seconds or "unlimited",
            )
        if self._max_elapsed_seconds is not None:
            self._store.reopen_elapsed_budget_failures(exact, self._max_elapsed_seconds)
        if self._max_tokens == "unlimited":
            self._store.reopen_token_budget_failures(exact)
        self._reopen_failed_anchor_verification(exact)
        static_checkpoint = self._store.get(identity, SimpleStage.STATIC_DONE)
        if (
            run.workspace_path is None
            or run.repository_profile_ref is None
            or run.static_bundle_ref is None
        ):
            return await self._run_static(run, identity)
        static = StaticBootstrapResult(
            repository_profile_ref=run.repository_profile_ref,
            static_bundle_ref=run.static_bundle_ref,
            workspace_path=run.workspace_path,
            static_coverage_ref=run.static_coverage_ref,
            static_disposition=run.static_disposition,
            security_policy_ref=run.security_policy_ref,
            policy_snapshot_ref=run.policy_snapshot_ref,
        )
        if run.candidate_pipeline_version in {1, 2}:
            if run.candidate_pipeline_version == 2:
                return await self._run_candidate_pipeline(run, identity, static)
            if run.static_disposition == "PARTIAL":
                try:
                    downstream_terminal = self._candidate_downstream_terminal(
                        run, identity, static
                    )
                except ChainingEvidenceInvalid as error:
                    failed = self._block_invalid_chaining(error.checkpoint)
                    return self._bootstrap_outcome(run, failed)
                if downstream_terminal:
                    try:
                        artifacts = SimpleArtifactRepository(self._data_dir, identity)
                        bundle = json.loads(artifacts.read(run.static_bundle_ref))
                        ast_summary = (
                            bundle.get("ast_summary")
                            if isinstance(bundle, dict)
                            else None
                        )
                    except (OSError, ValueError, TypeError):
                        return self._invalid_partial_resume(run, identity)
                    if (
                        isinstance(ast_summary, dict)
                        and "format_version" not in ast_summary
                        and isinstance(ast_summary.get("facts"), list)
                    ):
                        # Old candidate decisions must not be relabeled as
                        # reviewed against a newly sharded AST bundle.
                        return SimpleAnalysisOutcome(
                            identity=identity,
                            display_analysis_id=run.display_analysis_id,
                            status="PARTIAL",
                            current_stage=SimpleStage.HYPOTHESIS_DONE,
                            error_code="AST_FORMAT_UPGRADE_NEW_ANALYSIS_REQUIRED",
                        )
                    return await self._run_static(run, identity)
            return await self._run_candidate_pipeline(run, identity, static)
        retry_partial_static = run.static_disposition == "PARTIAL"
        if (
            retry_partial_static
            and static_checkpoint is not None
            and static_checkpoint.status is StageStatus.SUCCEEDED
        ):
            # Finish incomplete Agent/PoC work with its validated static input.
            # Once downstream is terminal, resume may refine static gaps.
            retry_partial_static = self._downstream_terminal(run)
            if retry_partial_static:
                # Chaining may have completed just before the process stopped,
                # leaving its children outside the durable hypothesis queue.
                try:
                    for hypothesis_id in run.hypothesis_ids:
                        child = identity.model_copy(
                            update={"hypothesis_id": hypothesis_id}
                        )
                        run = self._register_chain_children(
                            run, child, self._static_for_child(static, child)
                        )
                except ChainingEvidenceInvalid as error:
                    failed = self._block_invalid_chaining(error.checkpoint)
                    return self._bootstrap_outcome(run, failed)
                retry_partial_static = self._downstream_terminal(run)
        if retry_partial_static:
            return await self._run_static(run, identity)
        if not run.hypothesis_ids:
            return await self._propose_and_run(run, identity, static)
        hypothesis_checkpoint = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            hypothesis_checkpoint is not None
            and hypothesis_checkpoint.status is not StageStatus.SUCCEEDED
        ):
            try:
                return await self._propose_and_run(
                    run, identity, static, append_existing=True
                )
            except StaticEvidenceInvalid:
                return self._invalid_hypothesis_resume(run, identity)
        return await self._run_hypotheses(run, identity, static)

    def _reopen_failed_anchor_verification(self, analysis_id: str) -> None:
        """Retry fixed anchor validation without replaying prior child work."""

        for checkpoint in self._store.list_checkpoints(analysis_id):
            if (
                checkpoint.identity.hypothesis_id is None
                or checkpoint.stage
                not in {
                    SimpleStage.VERIFICATION_INITIAL_DONE,
                    SimpleStage.VERIFICATION_FINAL_DONE,
                }
                or checkpoint.status is not StageStatus.FAILED
                or checkpoint.error_code != "HYPOTHESIS_ANCHOR_INVALID"
                or checkpoint.attempt_number >= MAX_RECOVERY_ATTEMPTS
            ):
                continue
            self._store.replace_from(
                checkpoint.model_copy(
                    update={
                        "stage_version": STAGE_VERSION[checkpoint.stage],
                        "status": StageStatus.PENDING,
                        "output_refs": (),
                        "attempt_id": None,
                        "error_code": None,
                        "retryable": False,
                    }
                )
            )

    def _downstream_terminal(self, run: SimpleAnalysisRun) -> bool:
        if not run.hypothesis_ids:
            return False
        children: dict[str, dict[SimpleStage, StageCheckpoint]] = {
            hypothesis_id: {} for hypothesis_id in run.hypothesis_ids
        }
        for checkpoint in self._store.list_checkpoints(run.analysis_id):
            if checkpoint.status is not StageStatus.SUCCEEDED:
                return False
            hypothesis_id = checkpoint.identity.hypothesis_id
            if hypothesis_id not in children:
                continue
            if checkpoint.stage_version != STAGE_VERSION[checkpoint.stage]:
                return False
            children[hypothesis_id][checkpoint.stage] = checkpoint
        for stages in children.values():
            initial = stages.get(SimpleStage.VERIFICATION_INITIAL_DONE)
            final = stages.get(SimpleStage.VERIFICATION_FINAL_DONE)
            chaining = stages.get(SimpleStage.CHAINING_DONE)
            report = stages.get(SimpleStage.REPORT_DONE)
            if (
                self._store.verified_terminal_initial_outcome(initial) is not None
                or self._store.verified_terminal_poc_outcome(
                    stages.get(SimpleStage.POC_EXECUTION_DONE)
                )
                is not None
                or final is not None
                and (
                    final.verdict == "FALSE"
                    or final.verdict == "HOLD"
                    and chaining is not None
                )
                or terminal_gate_outcome(stages.get(SimpleStage.TECH_GATE_DONE))
                is not None
                or report is not None
            ):
                continue
            return False
        return True

    def _invalid_partial_resume(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> SimpleAnalysisOutcome:
        checkpoint = self._store.require(identity, SimpleStage.STATIC_DONE)
        failed = self._store.mark_failure(
            checkpoint,
            StageFailure(
                code="STATIC_EVIDENCE_INVALID",
                retryable=False,
                safe_message="Stored static evidence cannot be trusted",
            ),
            StageStatus.BLOCKED,
        )
        return self._bootstrap_outcome(run, failed)

    def _invalid_hypothesis_resume(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> SimpleAnalysisOutcome:
        checkpoint = self._store.require(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            checkpoint.status is StageStatus.BLOCKED
            and checkpoint.error_code == "HYPOTHESIS_EVIDENCE_INVALID"
        ):
            return self._bootstrap_outcome(run, checkpoint)
        failed = self._store.mark_failure(
            checkpoint,
            StageFailure(
                code="HYPOTHESIS_EVIDENCE_INVALID",
                retryable=False,
                safe_message="Stored hypothesis evidence cannot be trusted",
            ),
            StageStatus.BLOCKED,
            activity_attempt_id=f"integrity-audit-{uuid4().hex}",
        )
        return self._bootstrap_outcome(run, failed)

    def _reconcile_hypothesis_checkpoint(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> SimpleAnalysisRun:
        checkpoint = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if checkpoint is None or checkpoint.status is not StageStatus.SUCCEEDED:
            return run
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        known = set(run.hypothesis_ids)
        added: list[str] = []
        for ref in checkpoint.output_refs:
            try:
                payload = json.loads(artifacts.read_prompt_proposal(ref))
                if (
                    not isinstance(payload, dict)
                    or payload.get("kind") != "simple_hypothesis_proposal"
                    or not isinstance(payload.get("hypothesis_id"), str)
                ):
                    raise StaticEvidenceInvalid()
                hypothesis_id = payload["hypothesis_id"]
                static_ref_data = payload.get("static_bundle_ref")
                static_ref = (
                    StoredDataRef.model_validate(static_ref_data)
                    if static_ref_data is not None
                    else checkpoint.input_refs[0]
                )
                if not isinstance(static_ref, StoredDataRef):
                    raise StaticEvidenceInvalid()
            except (OSError, ValueError, KeyError, IndexError) as error:
                raise StaticEvidenceInvalid() from error
            if hypothesis_id in known:
                continue
            child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
            inputs = (ref, static_ref)
            existing = self._store.get(child, SimpleStage.PRO_CON_DONE)
            if existing is not None and existing.input_refs[:2] != inputs:
                raise StaticEvidenceInvalid()
            if existing is None:
                self._store.save_checkpoint(
                    StageCheckpoint(
                        identity=child,
                        stage=SimpleStage.PRO_CON_DONE,
                        status=StageStatus.PENDING,
                        input_refs=inputs,
                        input_hash=input_reference_hash(inputs),
                    )
                )
            known.add(hypothesis_id)
            added.append(hypothesis_id)
        if not added:
            return run
        updated = run.model_copy(
            update={"hypothesis_ids": run.hypothesis_ids + tuple(added)}
        )
        self._store.save_analysis_run(updated)
        return updated

    def _verify_registered_candidate_proposals(
        self, identity: CheckpointIdentity
    ) -> None:
        """Do not skip a completed candidate whose original evidence is gone."""

        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        after_id: str | None = None
        while True:
            ids = self._store.list_hypotheses(identity, after_id=after_id, limit=64)
            if not ids:
                return
            for hypothesis_id in ids:
                after_id = hypothesis_id
                child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                checkpoint = self._store.get(child, SimpleStage.PRO_CON_DONE)
                if checkpoint is None or not checkpoint.input_refs:
                    raise StaticEvidenceInvalid()
                proposal = json.loads(
                    artifacts.read_prompt_proposal(checkpoint.input_refs[0])
                )
                if (
                    proposal.get("hypothesis_id") != hypothesis_id
                    or proposal.get("analysis_id") != identity.analysis_id
                ):
                    raise StaticEvidenceInvalid()

    async def _repair_invalid_saved_pro_con(self, analysis_id: str) -> None:
        """Reopen only intact legacy role results citing unavailable hashes."""

        repairs: list[
            tuple[
                StageCheckpoint,
                dict[str, StoredDataRef],
                dict[str, StoredDataRef | None],
            ]
        ] = []
        incomplete_repairs: list[
            tuple[
                StageCheckpoint,
                dict[str, StoredDataRef],
                dict[str, StoredDataRef | None],
            ]
        ] = []
        for checkpoint in self._store.list_checkpoints(analysis_id):
            if (
                checkpoint.stage is not SimpleStage.PRO_CON_DONE
                or checkpoint.status
                not in {StageStatus.SUCCEEDED, StageStatus.PENDING, StageStatus.BLOCKED}
            ):
                continue
            if (
                checkpoint.identity.hypothesis_id is None
                or checkpoint.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
                or (
                    checkpoint.status is StageStatus.SUCCEEDED
                    and len(checkpoint.output_refs) != 2
                )
            ):
                raise StaticEvidenceInvalid()
            artifacts = SimpleArtifactRepository(self._data_dir, checkpoint.identity)
            # This audit path only reads saved artifacts; it never invokes a model.
            stage = ProConStage(
                cast(SimpleLLMClient, None), artifacts, store=self._store
            )
            invalid: dict[str, StoredDataRef] = {}
            expected_cache: dict[str, StoredDataRef | None] = {}
            prior = self._store.prior(checkpoint.identity, SimpleStage.PRO_CON_DONE)
            roles: tuple[Literal["pro", "con"], ...] = ("pro", "con")
            for index, role in enumerate(roles):
                cached = self._store.get_pro_con_batch_evidence(
                    checkpoint.identity, role, checkpoint.input_hash
                )
                expected_cache[role] = cached
                # Incomplete checkpoints store failure evidence in output_refs;
                # only the persisted role cache can identify reusable results.
                evidence_ref = (
                    checkpoint.output_refs[index]
                    if checkpoint.status is StageStatus.SUCCEEDED
                    else cached
                )
                if (
                    checkpoint.status is StageStatus.SUCCEEDED
                    and cached is not None
                    and cached != evidence_ref
                ):
                    raise StaticEvidenceInvalid()
                if evidence_ref is None:
                    continue
                try:
                    await stage.validate_cached_role_evidence(
                        role, checkpoint, evidence_ref, prior
                    )
                except StageBlocked as error:
                    if error.failure.invalid_field != "evidence_refs" or not isinstance(
                        error.__cause__, ProConEvidenceRefInvalid
                    ):
                        raise StaticEvidenceInvalid() from error
                    envelope = json.loads(artifacts.read(evidence_ref))
                    if (
                        not isinstance(envelope, dict)
                        or "batch_response_ref" in envelope
                    ):
                        raise StaticEvidenceInvalid() from error
                    envelope_attempt = envelope.get("attempt_id")
                    # A cached role may have succeeded in an earlier stage
                    # attempt. Its exact source refs and cache key bind it here.
                    if envelope_attempt is not None and (
                        not isinstance(envelope_attempt, str)
                        or not envelope_attempt.strip()
                    ):
                        raise StaticEvidenceInvalid() from error
                    invalid[role] = evidence_ref
            if invalid:
                if checkpoint.status is StageStatus.SUCCEEDED:
                    repairs.append((checkpoint, invalid, expected_cache))
                else:
                    incomplete_repairs.append((checkpoint, invalid, expected_cache))
        for checkpoint, invalid, expected_cache in repairs:
            if self._store.get(checkpoint.identity, SimpleStage.PRO_CON_DONE) is None:
                # An earlier repaired ancestor retracted this child in the
                # same resume pass; it must not be replayed independently.
                root = checkpoint.identity.model_copy(update={"hypothesis_id": None})
                if not self._store.has_hypothesis(
                    root, checkpoint.identity.hypothesis_id or ""
                ):
                    continue
                raise StaticEvidenceInvalid()
            try:
                self._store.repair_legacy_pro_con_evidence(
                    checkpoint, invalid, expected_role_cache=expected_cache
                )
            except (OSError, ValueError, sqlite3.Error) as error:
                raise StaticEvidenceInvalid() from error
        for checkpoint, invalid, expected_cache in incomplete_repairs:
            if self._store.get(checkpoint.identity, SimpleStage.PRO_CON_DONE) is None:
                root = checkpoint.identity.model_copy(update={"hypothesis_id": None})
                if not self._store.has_hypothesis(
                    root, checkpoint.identity.hypothesis_id or ""
                ):
                    continue
                raise StaticEvidenceInvalid()
            try:
                self._store.repair_pending_pro_con_role_cache(
                    checkpoint, invalid, expected_role_cache=expected_cache
                )
            except (OSError, ValueError, sqlite3.Error) as error:
                raise StaticEvidenceInvalid() from error

    async def _assert_completed_static_scope(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> None:
        """Do not resume completed agents against an obsolete static denominator."""

        fingerprint_method = getattr(self._static, "coverage_fingerprint", None)
        if fingerprint_method is None:
            return
        assert run.static_bundle_ref is not None
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            bundle = json.loads(artifacts.read(run.static_bundle_ref))
            if (
                not isinstance(bundle, dict)
                or bundle.get("kind") != "simple_static_fact_bundle"
            ):
                raise ValueError
            coverage_ref = StoredDataRef.model_validate(bundle["static_coverage_ref"])
            coverage = json.loads(artifacts.read(coverage_ref))
            if (
                not isinstance(coverage, dict)
                or coverage.get("kind") != "simple_static_coverage_v1"
                or not isinstance(coverage.get("fingerprint"), str)
            ):
                raise ValueError
            current = await fingerprint_method(
                SimpleAnalysisRequest(
                    data_dir=self._data_dir,
                    repository=run.repository,
                    commit=run.commit_id,
                ),
                identity,
            )
        except (OSError, RuntimeError, ValueError, KeyError, TypeError):
            raise ValueError("STATIC_SCOPE_VALIDATION_FAILED") from None
        if coverage["fingerprint"] != current:
            raise ValueError("STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED")

    def _validate_static_evidence(
        self, static: StaticBootstrapResult, identity: CheckpointIdentity
    ) -> None:
        """Do not publish a partial or complete claim against invalid evidence."""

        if static.static_coverage_ref is None:
            if static.static_disposition == "PARTIAL":
                raise StaticEvidenceInvalid()
            return  # Legacy full bootstrap implementations have no coverage ref.
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            coverage = json.loads(artifacts.read(static.static_coverage_ref))
            if not isinstance(bundle, dict) or not isinstance(coverage, dict):
                raise StaticEvidenceInvalid()
            if bundle.get("kind") != "simple_static_fact_bundle":
                raise StaticEvidenceInvalid()
            if coverage.get("kind") != "simple_static_coverage_v1":
                raise StaticEvidenceInvalid()
            if any(
                bundle.get(key) != value or coverage.get(key) != value
                for key, value in (
                    ("analysis_id", identity.analysis_id),
                    ("workspace_id", identity.workspace_id),
                    ("commit_id", identity.commit_id),
                )
            ):
                raise StaticEvidenceInvalid()
            recorded_ref = StoredDataRef.model_validate(bundle["static_coverage_ref"])
            if recorded_ref != static.static_coverage_ref:
                raise StaticEvidenceInvalid()
            expected = coverage.get("expected_count")
            verified = coverage.get("verified_count")
            gaps = coverage.get("gaps")
            unsupported = coverage.get("unsupported")
            unavailable_paths = coverage.get("unavailable_paths", [])
            if (
                not isinstance(coverage.get("fingerprint"), str)
                or type(expected) is not int
                or type(verified) is not int
                or expected < 0
                or not 0 <= verified <= expected
                or not isinstance(gaps, list)
                or not isinstance(unsupported, list)
                or not isinstance(unavailable_paths, list)
                or len(gaps) != expected - verified
            ):
                raise StaticEvidenceInvalid()
            if any(
                not isinstance(gap, dict)
                or not all(
                    isinstance(gap.get(key), str)
                    for key in ("path", "rule_id", "reason")
                )
                or gap["reason"] == "source_unavailable"
                for gap in gaps
            ):
                raise StaticEvidenceInvalid()
            if any(
                not isinstance(item, dict)
                or not all(
                    isinstance(item.get(key), str) and item[key]
                    for key in ("path", "reason")
                )
                for item in unavailable_paths
            ):
                raise StaticEvidenceInvalid()
            unavailable = coverage.get("unavailable") is True
            if unavailable and not unavailable_paths:
                raise StaticEvidenceInvalid()
            ast_summary = bundle.get("ast_summary")
            parsed = (
                ast_summary.get("parsed_file_count", 0)
                if isinstance(ast_summary, dict)
                else 0
            )
            if type(parsed) is not int or parsed < 0:
                raise StaticEvidenceInvalid()
            recorded_parsed = coverage.get("ast_parsed_file_count")
            if recorded_parsed is not None and recorded_parsed != parsed:
                raise StaticEvidenceInvalid()
            if isinstance(ast_summary, dict):
                validate_ast_manifest(artifacts, ast_summary)
                if ast_summary.get("format_version") in {2, 3}:
                    if type(recorded_parsed) is not int or recorded_parsed != parsed:
                        raise StaticEvidenceInvalid()
                    source_ref = StoredDataRef.model_validate(
                        bundle["source_manifest_ref"]
                    )
                    source_manifest = json.loads(artifacts.read(source_ref))
                    if (
                        not isinstance(source_manifest, dict)
                        or source_manifest.get("kind") != "simple_tracked_sources"
                        or not isinstance(source_manifest.get("paths"), list)
                    ):
                        raise StaticEvidenceInvalid()
                    selected_paths = source_manifest["paths"]
                    if any(not isinstance(path, str) for path in selected_paths):
                        raise StaticEvidenceInvalid()
                    python_paths = {
                        path
                        for path in selected_paths
                        if path.lower().endswith((".py", ".pyi"))
                    }
                    if len(set(selected_paths)) != len(selected_paths):
                        raise StaticEvidenceInvalid()
                    parsed_paths = set(index_ast_manifest(artifacts, ast_summary))
                    error_paths = ast_summary.get("parse_errors")
                    oversize_paths = ast_summary.get("oversize_paths")
                    if not isinstance(error_paths, list) or not isinstance(
                        oversize_paths, list
                    ):
                        raise StaticEvidenceInvalid()
                    for paths, summary_count, coverage_paths, coverage_count in (
                        (
                            error_paths,
                            ast_summary.get("parse_error_count"),
                            coverage.get("ast_parse_errors"),
                            coverage.get("ast_parse_error_count"),
                        ),
                        (
                            oversize_paths,
                            ast_summary.get("oversize_count"),
                            coverage.get("ast_oversize_paths"),
                            coverage.get("ast_oversize_count"),
                        ),
                    ):
                        if (
                            not isinstance(paths, list)
                            or any(
                                not isinstance(path, str) or not path for path in paths
                            )
                            or type(summary_count) is not int
                            or summary_count != len(paths)
                            or type(coverage_count) is not int
                            or coverage_count != summary_count
                            or coverage_paths != paths
                            or len(set(paths)) != len(paths)
                        ):
                            raise StaticEvidenceInvalid()
                    if (
                        parsed_paths & set(error_paths)
                        or parsed_paths & set(oversize_paths)
                        or set(error_paths) & set(oversize_paths)
                        or parsed_paths | set(error_paths) | set(oversize_paths)
                        != python_paths
                        or coverage.get("ast_truncated") is not False
                    ):
                        raise StaticEvidenceInvalid()
            codeql_proof = False
            if (
                bundle.get("codeql_executed") is True
                and coverage.get("codeql_executed") is True
            ):
                tool_refs = bundle.get("tool_result_refs")
                if isinstance(tool_refs, list) and len(tool_refs) >= 3:
                    codeql_ref = StoredDataRef.model_validate(tool_refs[2])
                    artifacts.read(codeql_ref)
                    codeql_proof = True
            independent_verified = parsed > 0 or codeql_proof
            has_limitations = bool(
                gaps
                or unsupported
                or unavailable
                or unavailable_paths
                or expected == 0
                or verified == 0
                or coverage.get("unsupported_files")
                or coverage.get("codeql_error")
                or coverage.get("ast_parse_error_count")
                or coverage.get("ast_oversize_count")
                or coverage.get("ast_truncated")
                or coverage.get("out_of_scope_product_files")
            )
            if static.static_disposition == "PARTIAL":
                if (verified == 0 and not independent_verified) or not has_limitations:
                    raise StaticEvidenceInvalid()
            elif has_limitations:
                raise StaticEvidenceInvalid()
        except (OSError, ValueError, KeyError, TypeError) as error:
            if isinstance(error, StaticEvidenceInvalid):
                raise
            raise StaticEvidenceInvalid() from error

    def _hypothesis_static_ref(
        self, identity: CheckpointIdentity
    ) -> StoredDataRef | None:
        checkpoint = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if checkpoint is None or not checkpoint.input_refs:
            return None
        return checkpoint.input_refs[0]

    def _static_facts_changed(
        self,
        identity: CheckpointIdentity,
        old_ref: StoredDataRef,
        new_ref: StoredDataRef,
    ) -> bool:
        if old_ref == new_ref:
            return False
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            old = json.loads(artifacts.read(old_ref))
            new = json.loads(artifacts.read(new_ref))
            if not isinstance(old, dict) or not isinstance(new, dict):
                raise StaticEvidenceInvalid()
            if (
                old.get("kind") != "simple_static_fact_bundle"
                or new.get("kind") != "simple_static_fact_bundle"
            ):
                raise StaticEvidenceInvalid()
            keys = ("ast_summary", "opengrep_findings", "codeql_findings")
            return canonical_bytes(
                {key: old.get(key) for key in keys}
            ) != canonical_bytes({key: new.get(key) for key in keys})
        except (OSError, ValueError, TypeError) as error:
            if isinstance(error, StaticEvidenceInvalid):
                raise
            raise StaticEvidenceInvalid() from error

    def _promote_legacy_inconclusive_pocs(self, analysis_id: str) -> int:
        """Reclassify verified exhausted or explicitly stopped inconclusive PoCs."""

        promoted = 0
        for checkpoint in self._store.list_checkpoints(analysis_id):
            if (
                checkpoint.stage is not SimpleStage.POC_EXECUTION_DONE
                or checkpoint.stage_version
                != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
                or checkpoint.status is not StageStatus.BLOCKED
                or checkpoint.error_code
                not in {"RECOVERY_EXHAUSTED", "POC_INCONCLUSIVE"}
                or len(checkpoint.output_refs) != 2
                or checkpoint.validated_poc_ref is not None
            ):
                continue
            artifacts = SimpleArtifactRepository(self._data_dir, checkpoint.identity)
            if checkpoint.error_code == "POC_INCONCLUSIVE":
                try:
                    self._store.promote_inconclusive_execution(
                        checkpoint, artifacts=artifacts
                    )
                except ValueError as error:
                    if str(error) not in {
                        "POC_INCONCLUSIVE_PROMOTION_STALE",
                        "POC_INCONCLUSIVE_STOP_UNVERIFIED",
                        "POC_INCONCLUSIVE_PROMOTION_INVALID",
                    }:
                        raise
                    continue
                promoted += 1
                continue
            if checkpoint.attempt_number < MAX_RECOVERY_ATTEMPTS:
                continue
            execution_ref, interpretation_ref = checkpoint.output_refs
            try:
                execution = json.loads(artifacts.read(execution_ref))
                interpretation = json.loads(artifacts.read(interpretation_ref))
            except (OSError, ValueError, sqlite3.Error):
                continue
            if not isinstance(execution, dict) or not isinstance(interpretation, dict):
                continue
            result = interpretation.get("result")
            exit_code = execution.get("exit_code")
            if (
                execution.get("kind") != "simple_poc_execution"
                or execution.get("attempt_id") != checkpoint.attempt_id
                or execution.get("timed_out") is not False
                or type(exit_code) is not int
                or exit_code != 0
                or interpretation.get("kind") != "simple_dynamic_interpretation"
                or interpretation.get("execution_ref")
                != execution_ref.model_dump(mode="json")
                or not isinstance(result, dict)
                or result.get("outcome") != "INCONCLUSIVE"
            ):
                continue
            try:
                self._store.promote_inconclusive_execution(checkpoint)
            except ValueError as error:
                if str(error) != "POC_INCONCLUSIVE_PROMOTION_STALE":
                    raise
                continue
            promoted += 1
        return promoted

    def _candidate_downstream_terminal(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> bool:
        scope = run.candidate_scope_fingerprint
        if scope is None:
            return False
        checkpoint = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if checkpoint is None or checkpoint.status is not StageStatus.SUCCEEDED:
            return False
        counts = self._store.candidate_counts(identity, scope)
        deep = self._store.candidate_deep_counts(identity, scope)
        if (
            counts.get("PENDING", 0)
            or counts.get("ERROR", 0)
            or any(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
        ):
            return False
        progress = self._store.survey_progress(
            identity.analysis_id, static.static_bundle_ref.content_hash
        )
        try:
            free_done = self._candidate_free_done_valid(identity, static, progress)
        except (OSError, ValueError, TypeError, sqlite3.Error):
            return False
        if not free_done:
            return False
        self._recover_candidate_chains(run, identity, static)
        return not self._store.list_incomplete_hypotheses(identity, limit=1)

    async def _run_candidate_pipeline(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        try:
            if run.candidate_terminal is not None:
                run = run.model_copy(update={"candidate_terminal": None})
                self._store.save_analysis_run(run)
            outcome = await self._run_candidate_pipeline_inner(run, identity, static)
            return self._finalize_candidate_exit(identity, outcome)
        except ChainingEvidenceInvalid as error:
            failed = self._block_invalid_chaining(error.checkpoint)
            return self._finalize_candidate_exit(
                identity, self._bootstrap_outcome(run, failed)
            )
        except Exception as error:
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                self._safe_error_code(error, "CANDIDATE_PIPELINE_ERROR"),
            )

    def _finalize_candidate_exit(
        self, identity: CheckpointIdentity, outcome: SimpleAnalysisOutcome
    ) -> SimpleAnalysisOutcome:
        if outcome.status in {"PAUSED", "BLOCKED", "FAILED"}:
            root = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
            if root is not None and root.status is StageStatus.RUNNING:
                code = outcome.error_code or "CANDIDATE_CHILD_WORK_INCOMPLETE"
                if code in {
                    "CODEX_CALL_IN_FLIGHT_UNRESOLVED",
                    "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                }:
                    # The actual child has the process-bound confirmation.
                    # Copying this code to the root creates an unconfirmable
                    # second checkpoint and prevents a safe same-ID resume.
                    code = "CANDIDATE_CHILD_CODEX_STATE_PENDING"
                    if outcome.child_hypothesis_id and outcome.child_attempt_id:
                        code += (
                            f":{outcome.child_hypothesis_id}:{outcome.child_attempt_id}"
                        )
                elif code not in BUDGET_PAUSE_CODES:
                    if outcome.child_hypothesis_id and outcome.child_attempt_id:
                        code = (
                            f"CANDIDATE_CHILD_ERROR_BOUND:{code}"
                            f":{outcome.child_hypothesis_id}:{outcome.child_attempt_id}"
                        )
                    else:
                        code = f"CANDIDATE_CHILD_ERROR:{code}"
                self._store.mark_failure(
                    root,
                    StageFailure(
                        code=code,
                        retryable=False,
                        safe_message="Candidate child analysis did not complete",
                    ),
                    (
                        StageStatus.FAILED
                        if outcome.status == "FAILED"
                        else StageStatus.BLOCKED
                    ),
                )
        return outcome

    async def _run_candidate_pipeline_inner(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        """New-run path: retain every static hit and checkpoint Discovery separately."""

        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            if static.static_coverage_ref is None:
                raise ValueError("CANDIDATE_COVERAGE_MISSING")
            coverage = json.loads(artifacts.read(static.static_coverage_ref))
            if not isinstance(coverage, dict):
                raise ValueError("CANDIDATE_COVERAGE_INVALID")
            scope = coverage.get("fingerprint")
            if not isinstance(scope, str) or not scope:
                raise ValueError("CANDIDATE_COVERAGE_INVALID")
            if run.candidate_scope_fingerprint not in (None, scope):
                raise ValueError("CANDIDATE_SCOPE_CHANGED")
            if run.candidate_scope_fingerprint is None:
                run = run.model_copy(update={"candidate_scope_fingerprint": scope})
                self._store.save_analysis_run(run)
            saved_candidates = self._store.list_candidates(identity, scope, limit=1)
            identity_version = (
                "legacy"
                if saved_candidates
                and not saved_candidates[0].evidence_key.startswith("exact-v2:")
                else "exact-v2"
            )
            ingest_static_candidates(
                identity,
                scope,
                static.static_bundle_ref,
                artifacts,
                self._store,
                workspace=static.workspace_path,
                identity_version=identity_version,
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                self._safe_error_code(error, "CANDIDATE_EVIDENCE_INVALID"),
            )
        if self._candidate_client_factory is None:
            return self._candidate_bootstrap_failure(
                run, identity, static, "DISCOVERY_CLIENT_UNAVAILABLE"
            )
        bundle = json.loads(artifacts.read(static.static_bundle_ref))
        ast_summary = bundle.get("ast_summary") if isinstance(bundle, dict) else None
        ast_index = (
            index_ast_manifest(artifacts, ast_summary)
            if isinstance(ast_summary, dict) and "format_version" in ast_summary
            else None
        )
        surface_index: SurfaceIndex | None = None
        surface_index_ref: StoredDataRef | None = None
        if run.candidate_pipeline_version == 2 and isinstance(ast_summary, dict):
            surface_index, surface_index_ref = self._ensure_attack_surface_index(
                identity, static, scope, artifacts, bundle, ast_summary
            )
        prior = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            prior is None
            or prior.status is not StageStatus.SUCCEEDED
            or prior.input_refs != (static.static_bundle_ref,)
        ):
            checkpoint = self._store.mark_running(
                identity,
                SimpleStage.HYPOTHESIS_DONE,
                (static.static_bundle_ref,),
                attempt_id=uuid4().hex,
            )
        else:
            checkpoint = prior
        client = self._candidate_client_factory(identity, artifacts)
        discovery = await CandidateDiscovery(
            store=self._store, artifacts=artifacts, client=client
        ).run(
            identity,
            scope,
            retry_errors=prior is not None
            and prior.status in {StageStatus.BLOCKED, StageStatus.FAILED},
        )
        if discovery.status != "COMPLETE":
            code = discovery.error_code or "DISCOVERY_INCOMPLETE"
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                code,
                paused=discovery.status == "PAUSED",
                evidence_refs=discovery.evidence_refs,
                current_checkpoint=checkpoint,
            )
        if run.candidate_pipeline_version == 2:
            if surface_index is None or surface_index_ref is None:
                raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID")
            return await self._run_candidate_batches_v2(
                run,
                identity,
                static,
                scope,
                artifacts,
                ast_summary,
                surface_index,
                surface_index_ref,
                checkpoint,
            )
        after_id: str | None = None
        while True:
            page = self._store.list_candidates(
                identity,
                scope,
                status=("INCLUDE", "UNDECIDED"),
                after_id=after_id,
                limit=32,
            )
            if not page:
                break
            for candidate in page:
                after_id = candidate.candidate_id
                if candidate.deep_status in {"COMPLETE", "NO_HYPOTHESIS"}:
                    continue
                links = self._store.list_candidate_hypothesis_ids(
                    identity, scope, candidate.candidate_id, limit=1
                )
                if links:
                    self._store.save_candidate_deep_status(
                        identity, scope, candidate.candidate_id, "RUNNING"
                    )
                    continue
                focused_data: dict[str, object] = {
                    "kind": "simple_static_fact_bundle",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "static_coverage_ref": static.static_coverage_ref.model_dump(
                        mode="json"
                    ),
                    "candidate_focus": CandidateDiscovery._projection(candidate),
                }
                if isinstance(ast_summary, dict) and "format_version" in ast_summary:
                    try:
                        focused_data["ast_focus"] = focus_ast_facts(
                            artifacts,
                            ast_summary,
                            path=candidate.path,
                            line=candidate.line,
                            manifest_index=ast_index,
                        )
                    except (OSError, ValueError, KeyError, TypeError):
                        return self._candidate_bootstrap_failure(
                            run,
                            identity,
                            static,
                            "AST_FOCUS_EVIDENCE_INVALID",
                            current_checkpoint=checkpoint,
                        )
                focused = artifacts.put_bytes(
                    redact_projected_json(canonical_bytes(focused_data)).data,
                    "application/json",
                )
                candidate_static = static.model_copy(
                    update={"static_bundle_ref": focused}
                )
                artifacts.prompt_context_strict((focused,))
                proposed = await self._candidate_hypotheses.propose(
                    identity, candidate_static
                )
                if isinstance(proposed, StageFailure):
                    budget_paused = proposed.code in BUDGET_PAUSE_CODES
                    if not budget_paused:
                        self._store.save_candidate_deep_status(
                            identity, scope, candidate.candidate_id, "ERROR"
                        )
                    return self._candidate_bootstrap_failure(
                        run,
                        identity,
                        static,
                        proposed.code,
                        paused=budget_paused,
                        evidence_refs=proposed.evidence_refs,
                        current_checkpoint=checkpoint,
                    )
                if not proposed:
                    self._store.save_candidate_deep_status(
                        identity, scope, candidate.candidate_id, "NO_HYPOTHESIS"
                    )
                    continue
                registrations: list[tuple[str, StoredDataRef, StageCheckpoint]] = []
                for seed in proposed:
                    artifacts.prompt_context_strict((seed.proposal_ref, focused))
                    inputs = (seed.proposal_ref, focused)
                    pending = StageCheckpoint(
                        identity=identity.model_copy(
                            update={"hypothesis_id": seed.hypothesis_id}
                        ),
                        stage=SimpleStage.PRO_CON_DONE,
                        status=StageStatus.PENDING,
                        input_refs=inputs,
                        input_hash=input_reference_hash(inputs),
                    )
                    registrations.append(
                        (seed.hypothesis_id, seed.proposal_ref, pending)
                    )
                self._store.register_candidate_hypotheses_batch(
                    identity, scope, candidate.candidate_id, registrations
                )
                self._store.save_candidate_deep_status(
                    identity, scope, candidate.candidate_id, "RUNNING"
                )
        free_failure = await self._run_free_candidate_exploration(
            identity, static, artifacts
        )
        if free_failure is not None:
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                free_failure.code,
                paused=free_failure.code in BUDGET_PAUSE_CODES,
                evidence_refs=free_failure.evidence_refs,
                current_checkpoint=checkpoint,
            )
        if checkpoint.status is not StageStatus.SUCCEEDED:
            completed = artifacts.put_json(
                {
                    "kind": "simple_candidate_discovery_complete",
                    "scope_fingerprint": scope,
                    "decision_counts": self._store.candidate_counts(identity, scope),
                }
            )
            self._store.complete(checkpoint, self._stage_result(completed))
        return await self._run_candidate_hypotheses(run, identity, static, scope)

    def _ensure_attack_surface_index(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
        artifacts: SimpleArtifactRepository,
        bundle: object,
        ast_summary: dict[str, object],
    ) -> tuple[SurfaceIndex, StoredDataRef]:
        """Build once from all static candidates; validate the exact replay set."""

        if not isinstance(bundle, dict):
            raise ValueError("SURFACE_STATIC_BUNDLE_INVALID")
        candidates: list[StaticCandidate] = []
        after_id: str | None = None
        while True:
            page = self._store.list_candidates(
                identity, scope, after_id=after_id, limit=128
            )
            if not page:
                break
            candidates.extend(page)
            after_id = page[-1].candidate_id
        inventory_hash = candidate_inventory_hash(candidates)
        ast_hash = hashlib.sha256(canonical_bytes(ast_summary)).hexdigest()
        existing = self._store.get_attack_surface_index(identity, scope)
        if existing is not None:
            if (
                existing.static_bundle_hash != static.static_bundle_ref.content_hash
                or existing.ast_manifest_hash != ast_hash
                or existing.candidate_inventory_hash != inventory_hash
                or existing.candidate_count != len(candidates)
            ):
                raise ValueError("SURFACE_INDEX_SCOPE_CHANGED")
            payload = json.loads(artifacts.read(existing.index_ref))
            index = surface_index_from_json(payload)
            if index.index_version == 2:
                manifest = index_ast_manifest(artifacts, ast_summary)
                expected_source_hashes = tuple(
                    (path, str(entry["source_sha256"]))
                    for path, entry in sorted(manifest.items())
                )
                if index.ast_source_hashes != expected_source_hashes:
                    raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID")
            if (
                not isinstance(payload, dict)
                or payload.get("kind")
                not in {
                    "simple_attack_surface_index_v1",
                    "simple_attack_surface_index_v2",
                }
                or payload.get("scope_fingerprint") != scope
                or payload.get("static_bundle_hash")
                != static.static_bundle_ref.content_hash
                or payload.get("ast_manifest_hash") != ast_hash
                or payload.get("candidate_inventory_hash") != inventory_hash
                or payload.get("candidate_count") != len(candidates)
                or index.index_version
                != (2 if ast_summary.get("format_version") == 3 else 1)
            ):
                raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID")
            return index, existing.index_ref
        index = build_attack_surface_index(
            bundle, ast_summary, candidates, artifacts=artifacts
        )
        if (
            index.scope_fingerprint != scope
            or index.static_bundle_hash != static.static_bundle_ref.content_hash
            or index.ast_manifest_hash != ast_hash
            or index.candidate_inventory_hash != inventory_hash
            or index.candidate_count != len(candidates)
        ):
            raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID")
        index_ref = artifacts.put_json(index.to_json())
        self._store.save_attack_surface_index(
            identity,
            scope,
            static_bundle_hash=index.static_bundle_hash,
            ast_manifest_hash=index.ast_manifest_hash,
            candidate_inventory_hash=index.candidate_inventory_hash,
            candidate_count=index.candidate_count,
            index_ref=index_ref,
        )
        return index, index_ref

    @staticmethod
    def _candidate_batch_source_hash(
        artifacts: SimpleArtifactRepository, batch: CandidateBatch
    ) -> str | None:
        context = json.loads(artifacts.read(batch.shared_context_ref))
        if (
            not isinstance(context, dict)
            or context.get("kind")
            not in {
                "simple_candidate_file_context_v1",
                "simple_candidate_file_context_v2",
            }
            or context.get("path") != batch.path
        ):
            raise ValueError("CANDIDATE_BATCH_CONTEXT_INVALID")
        source_hash = context.get("source_sha256")
        if source_hash is not None and (
            not isinstance(source_hash, str) or len(source_hash) != 64
        ):
            raise ValueError("CANDIDATE_BATCH_CONTEXT_INVALID")
        return source_hash

    @staticmethod
    def _candidate_batch_response_valid(
        artifacts: SimpleArtifactRepository,
        batch: CandidateBatch,
        candidate_id: str,
        status: str,
        result_ref: StoredDataRef,
    ) -> None:
        value = json.loads(artifacts.read(result_ref))
        if (
            not isinstance(value, dict)
            or value.get("kind") != "simple_candidate_batch_response_v1"
            or value.get("batch_id") != batch.batch_id
            or candidate_id not in value.get("requested_ids", [])
            or not isinstance(value.get("candidate_results"), list)
        ):
            raise ValueError("CANDIDATE_BATCH_RESPONSE_INVALID")
        matches = [
            row
            for row in value["candidate_results"]
            if isinstance(row, dict) and row.get("candidate_id") == candidate_id
        ]
        if len(matches) != 1 or matches[0].get("status") != status:
            raise ValueError("CANDIDATE_BATCH_RESPONSE_INVALID")

    async def _drain_candidate_children(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        *,
        attempted_in_turn: set[str],
        turn_id: str,
        max_runnable: int,
    ) -> RunOutcome | None:
        """Run each durable child at most once this turn; never finalize the run."""

        incomplete: RunOutcome | None = None
        attempted_count = 0
        while attempted_count < max_runnable:
            after_id: str | None = None
            made_progress = False
            while attempted_count < max_runnable:
                ids = self._store.list_incomplete_hypotheses(
                    identity, after_id=after_id, limit=32
                )
                if not ids:
                    break
                warmed = await self._prewarm_pro_con_batches(
                    identity, static, ids, attempted_in_turn
                )
                if warmed is not None:
                    return warmed
                for hypothesis_id in ids:
                    after_id = hypothesis_id
                    if hypothesis_id in attempted_in_turn:
                        continue
                    if not self._store.claim_hypothesis(
                        identity, hypothesis_id, turn_id
                    ):
                        continue
                    attempted_in_turn.add(hypothesis_id)
                    attempted_count += 1
                    made_progress = True
                    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                    try:
                        outcome = await self._runner_factory(
                            self._store,
                            child,
                            static,
                        ).resume_hypothesis(child)
                    finally:
                        self._store.release_hypothesis_claim(
                            identity, hypothesis_id, turn_id
                        )
                    outcome = outcome.model_copy(
                        update={"hypothesis_id": hypothesis_id}
                    )
                    if outcome.status in {StageStatus.BLOCKED, StageStatus.FAILED}:
                        if outcome.error_code in BUDGET_PAUSE_CODES:
                            return outcome
                        if (
                            incomplete is None
                            or outcome.status is StageStatus.FAILED
                            and incomplete.status is StageStatus.BLOCKED
                        ):
                            incomplete = outcome
                    else:
                        self._register_chain_children(run, child, static)
                    if attempted_count >= max_runnable:
                        break
            if not made_progress:
                break
        return incomplete

    async def _prewarm_pro_con_batches(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        hypothesis_ids: tuple[str, ...],
        attempted_in_turn: set[str],
    ) -> RunOutcome | None:
        """Share source context; preserve each child's independent checkpoint."""

        groups: dict[str, tuple[StoredDataRef, list[StageCheckpoint]]] = {}
        for hypothesis_id in hypothesis_ids:
            if hypothesis_id in attempted_in_turn:
                continue
            child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
            checkpoint = self._store.get(child, SimpleStage.PRO_CON_DONE)
            if (
                checkpoint is None
                or checkpoint.status is not StageStatus.PENDING
                or len(checkpoint.input_refs) < 2
            ):
                continue
            if any(
                (
                    cached := self._store.get_pro_con_batch_evidence(
                        child, role, checkpoint.input_hash
                    )
                )
                is not None
                and "batch_response_ref"
                not in json.loads(
                    SimpleArtifactRepository(self._data_dir, child).read(cached)
                )
                for role in ("pro", "con")
            ):
                # Individual legacy cache envelopes can be reused by the
                # normal runner, but are not valid batch-existing inputs.
                continue
            shared_ref = checkpoint.input_refs[1]
            group = groups.setdefault(shared_ref.content_hash, (shared_ref, []))
            group[1].append(checkpoint)
        for shared_ref, checkpoints in groups.values():
            for start in range(0, len(checkpoints), 8):
                chunk = checkpoints[start : start + 8]
                if len(chunk) < 2:
                    continue
                handler_owner = self._runner_factory(
                    self._store, chunk[0].identity, static
                )
                handlers = getattr(handler_owner, "handlers", {})
                handler = handlers.get(SimpleStage.PRO_CON_DONE)
                if handler is None or not all(
                    callable(getattr(handler, name, None))
                    for name in ("run_pro_batch", "run_con_batch")
                ):
                    continue
                selected = {
                    checkpoint.identity.hypothesis_id: checkpoint
                    for checkpoint in chunk
                    if checkpoint.identity.hypothesis_id is not None
                }
                for role in ("pro", "con"):
                    existing = {
                        hypothesis_id: ref
                        for hypothesis_id, checkpoint in selected.items()
                        if (
                            ref := self._store.get_pro_con_batch_evidence(
                                checkpoint.identity, role, checkpoint.input_hash
                            )
                        )
                        is not None
                    }
                    if len(existing) == len(selected):
                        continue
                    method = getattr(handler, f"run_{role}_batch")
                    try:
                        refs = await method(selected, shared_ref, existing=existing)
                    except (StageBlocked, StageFailed) as error:
                        completed = getattr(error, "completed_refs", {})
                        if not isinstance(completed, dict):
                            raise ValueError("PRO_CON_BATCH_RESULT_INVALID") from error
                        for hypothesis_id, ref in completed.items():
                            if hypothesis_id not in selected:
                                raise ValueError(
                                    "PRO_CON_BATCH_RESULT_INVALID"
                                ) from error
                            checkpoint = selected[hypothesis_id]
                            self._store.save_pro_con_batch_evidence(
                                checkpoint.identity, role, checkpoint.input_hash, ref
                            )
                        missing = tuple(
                            hypothesis_id
                            for hypothesis_id in selected
                            if hypothesis_id not in completed
                            and hypothesis_id not in existing
                        )
                        if not missing:
                            raise ValueError("PRO_CON_BATCH_RESULT_INVALID") from error
                        # Every missing member already consumed this turn's
                        # bounded batch attempt. Do not send it through the
                        # individual runner again before a new resume turn.
                        attempted_in_turn.update(missing)
                        child_checkpoint = selected[missing[0]]
                        running = self._store.mark_running(
                            child_checkpoint.identity,
                            SimpleStage.PRO_CON_DONE,
                            child_checkpoint.input_refs,
                            attempt_id=uuid4().hex,
                        )
                        status = (
                            StageStatus.BLOCKED
                            if isinstance(error, StageBlocked)
                            else StageStatus.FAILED
                        )
                        self._store.mark_failure(running, error.failure, status)
                        return RunOutcome(
                            current_stage=SimpleStage.PRO_CON_DONE,
                            status=status,
                            error_code=error.failure.code,
                            hypothesis_id=missing[0],
                            attempt_id=running.attempt_id,
                        )
                    except ValueError as error:
                        if str(error) == "PRO_CON_BATCH_CONTEXT_OVERFLOW":
                            # Individual legacy calls preserve coverage when a
                            # two-child prompt cannot fit the bounded batch.
                            continue
                        raise
                    if not isinstance(refs, dict) or set(refs) != set(selected):
                        raise ValueError("PRO_CON_BATCH_RESULT_INVALID")
                    for hypothesis_id, ref in refs.items():
                        checkpoint = selected[hypothesis_id]
                        self._store.save_pro_con_batch_evidence(
                            checkpoint.identity, role, checkpoint.input_hash, ref
                        )
        return None

    async def _run_candidate_batches_v2(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
        artifacts: SimpleArtifactRepository,
        ast_summary: object,
        surface_index: SurfaceIndex,
        surface_index_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
    ) -> SimpleAnalysisOutcome:
        """Produce durable batches; v2 completion awaits the surface stage."""

        if not isinstance(ast_summary, dict):
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                "AST_BATCH_MANIFEST_MISSING",
                current_checkpoint=checkpoint,
            )
        propose_batch = getattr(self._candidate_hypotheses, "propose_batch", None)
        if not callable(propose_batch):
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                "HYPOTHESIS_BATCH_UNAVAILABLE",
                current_checkpoint=checkpoint,
            )
        outcomes = self._store.list_candidate_batch_outcomes(identity, scope)
        progress = self._store.list_candidate_batch_progress(identity, scope)
        self._store.clear_stale_hypothesis_claims(identity)
        self._recover_candidate_chains(run, identity, static)
        self._invalidate_stale_report_coverage(run, identity)
        attempted_in_turn: set[str] = set()
        turn_id = uuid4().hex
        incomplete: RunOutcome | None = None
        seen_batch_ids: set[str] = set()
        seen_candidate_ids: set[str] = set()
        try:
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            value = (
                bundle.get("candidate_context_version")
                if isinstance(bundle, dict)
                else None
            )
            context_version = value if value in {2, 3, 4} else 1
        except (OSError, TypeError, ValueError):
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                "CANDIDATE_STATIC_BUNDLE_INVALID",
                current_checkpoint=checkpoint,
            )
        batches = iter_candidate_batches(
            self._store,
            identity,
            scope,
            artifacts=artifacts,
            ast_summary=ast_summary,
            workspace=static.workspace_path,
            max_prompt_bytes=128 * 1024,
            context_version=context_version,
        )
        for batch in batches:
            if batch.batch_id in seen_batch_ids:
                raise ValueError("CANDIDATE_BATCH_DUPLICATE")
            seen_batch_ids.add(batch.batch_id)
            seen_candidate_ids.update(batch.candidate_ids)
            source_hash = self._candidate_batch_source_hash(artifacts, batch)
            for candidate_id in batch.candidate_ids:
                prior_outcome = outcomes.get(candidate_id)
                if prior_outcome is None:
                    continue
                if (
                    prior_outcome.batch_id != batch.batch_id
                    or prior_outcome.static_bundle_hash
                    != static.static_bundle_ref.content_hash
                    or prior_outcome.source_sha256 != source_hash
                    or prior_outcome.context_hash
                    != batch.shared_context_ref.content_hash
                ):
                    raise ValueError("CANDIDATE_BATCH_SCOPE_CHANGED")
                self._candidate_batch_response_valid(
                    artifacts,
                    batch,
                    candidate_id,
                    prior_outcome.status,
                    prior_outcome.result_ref,
                )
            marker_ref = progress.get(batch.batch_id)
            if marker_ref is not None:
                marker = json.loads(artifacts.read(marker_ref))
                if (
                    not isinstance(marker, dict)
                    or marker.get("kind") != "simple_candidate_batch_progress_v2"
                    or marker.get("scope_fingerprint") != scope
                    or marker.get("batch_id") != batch.batch_id
                    or marker.get("static_bundle_hash")
                    != static.static_bundle_ref.content_hash
                    or marker.get("path") != batch.path
                    or marker.get("candidate_ids") != list(batch.candidate_ids)
                    or marker.get("shared_context_hash")
                    != batch.shared_context_ref.content_hash
                    or marker.get("source_sha256") != source_hash
                    or set(batch.candidate_ids) - outcomes.keys()
                ):
                    raise ValueError("CANDIDATE_BATCH_PROGRESS_INVALID")
                drained = await self._drain_candidate_children(
                    run,
                    identity,
                    static,
                    attempted_in_turn=attempted_in_turn,
                    turn_id=turn_id,
                    max_runnable=self._max_pending_candidate_children,
                )
                if drained is not None:
                    if drained.error_code in BUDGET_PAUSE_CODES:
                        return SimpleAnalysisOutcome(
                            identity=identity,
                            display_analysis_id=run.display_analysis_id,
                            status="PAUSED",
                            current_stage=drained.current_stage,
                            error_code=drained.error_code,
                            child_hypothesis_id=drained.hypothesis_id,
                            child_attempt_id=drained.attempt_id,
                        )
                    if (
                        incomplete is None
                        or drained.status is StageStatus.FAILED
                        and incomplete.status is StageStatus.BLOCKED
                    ):
                        incomplete = drained
                continue
            missing = tuple(
                candidate_id
                for candidate_id in batch.candidate_ids
                if candidate_id not in outcomes
            )
            if missing:
                pending_count = len(
                    self._store.list_incomplete_hypotheses(
                        identity, limit=self._max_pending_candidate_children + 1
                    )
                )
                if (
                    pending_count + len(batch.candidate_ids) * 4
                    > self._max_pending_candidate_children
                ):
                    return self._candidate_bootstrap_failure(
                        run,
                        identity,
                        static,
                        "CANDIDATE_BACKPRESSURE_BLOCKED",
                        current_checkpoint=checkpoint,
                    )
                raw_result = await propose_batch(
                    identity, static, batch, requested_ids=missing
                )
                if isinstance(raw_result, StageFailure):
                    if raw_result.code not in BUDGET_PAUSE_CODES:
                        for candidate_id in missing:
                            self._store.save_candidate_deep_status(
                                identity, scope, candidate_id, "ERROR"
                            )
                    return self._candidate_bootstrap_failure(
                        run,
                        identity,
                        static,
                        raw_result.code,
                        paused=raw_result.code in BUDGET_PAUSE_CODES,
                        evidence_refs=raw_result.evidence_refs,
                        current_checkpoint=checkpoint,
                    )
                result = cast("BatchProposalResult", raw_result)
                if set(result.results) - set(missing) or set(result.missing_ids) != (
                    set(missing) - set(result.results)
                ):
                    raise ValueError("CANDIDATE_BATCH_RESULT_IDS_INVALID")
                for candidate_id in missing:
                    item = result.results.get(candidate_id)
                    if item is None:
                        continue
                    self._candidate_batch_response_valid(
                        artifacts, batch, candidate_id, item.status, item.result_ref
                    )
                    registrations: list[tuple[str, StoredDataRef, StageCheckpoint]] = []
                    for seed in item.seeds:
                        artifacts.prompt_context_strict(
                            (seed.proposal_ref, batch.shared_context_ref)
                        )
                        inputs = (seed.proposal_ref, batch.shared_context_ref)
                        pending = StageCheckpoint(
                            identity=identity.model_copy(
                                update={"hypothesis_id": seed.hypothesis_id}
                            ),
                            stage=SimpleStage.PRO_CON_DONE,
                            status=StageStatus.PENDING,
                            input_refs=inputs,
                            input_hash=input_reference_hash(inputs),
                        )
                        registrations.append(
                            (seed.hypothesis_id, seed.proposal_ref, pending)
                        )
                    self._store.commit_candidate_batch_outcome(
                        identity,
                        scope,
                        candidate_id,
                        batch_id=batch.batch_id,
                        static_bundle_hash=static.static_bundle_ref.content_hash,
                        source_sha256=source_hash,
                        context_hash=batch.shared_context_ref.content_hash,
                        status=item.status,
                        result_ref=item.result_ref,
                        registrations=registrations,
                    )
                    outcomes = self._store.list_candidate_batch_outcomes(
                        identity, scope
                    )
                if result.failure is not None or result.missing_ids:
                    if result.failure is None or (
                        result.failure.code not in BUDGET_PAUSE_CODES
                    ):
                        drained = await self._drain_candidate_children(
                            run,
                            identity,
                            static,
                            attempted_in_turn=attempted_in_turn,
                            turn_id=turn_id,
                            max_runnable=self._max_pending_candidate_children,
                        )
                        if drained is not None and (
                            drained.error_code in BUDGET_PAUSE_CODES
                        ):
                            return SimpleAnalysisOutcome(
                                identity=identity,
                                display_analysis_id=run.display_analysis_id,
                                status="PAUSED",
                                current_stage=drained.current_stage,
                                error_code=drained.error_code,
                                child_hypothesis_id=drained.hypothesis_id,
                                child_attempt_id=drained.attempt_id,
                            )
                    for candidate_id in result.missing_ids:
                        if result.failure is not None and (
                            result.failure.code in BUDGET_PAUSE_CODES
                        ):
                            continue
                        self._store.save_candidate_deep_status(
                            identity, scope, candidate_id, "ERROR"
                        )
                    failure = result.failure or StageFailure(
                        code="HYPOTHESIS_BATCH_OUTPUT_INVALID",
                        retryable=False,
                        safe_message="Candidate results were omitted",
                    )
                    return self._candidate_bootstrap_failure(
                        run,
                        identity,
                        static,
                        failure.code,
                        paused=failure.code in BUDGET_PAUSE_CODES,
                        evidence_refs=tuple(
                            dict.fromkeys(
                                (*result.attempt_refs, *failure.evidence_refs)
                            )
                        ),
                        current_checkpoint=checkpoint,
                    )
            marker = artifacts.put_json(
                {
                    "kind": "simple_candidate_batch_progress_v2",
                    "scope_fingerprint": scope,
                    "batch_id": batch.batch_id,
                    "static_bundle_hash": static.static_bundle_ref.content_hash,
                    "path": batch.path,
                    "candidate_ids": list(batch.candidate_ids),
                    "shared_context_hash": batch.shared_context_ref.content_hash,
                    "source_sha256": source_hash,
                }
            )
            self._store.save_candidate_batch_progress(
                identity, scope, batch.batch_id, marker
            )
            drained = await self._drain_candidate_children(
                run,
                identity,
                static,
                attempted_in_turn=attempted_in_turn,
                turn_id=turn_id,
                max_runnable=self._max_pending_candidate_children,
            )
            if drained is not None:
                if drained.error_code in BUDGET_PAUSE_CODES:
                    return SimpleAnalysisOutcome(
                        identity=identity,
                        display_analysis_id=run.display_analysis_id,
                        status="PAUSED",
                        current_stage=drained.current_stage,
                        error_code=drained.error_code,
                        child_hypothesis_id=drained.hypothesis_id,
                        child_attempt_id=drained.attempt_id,
                    )
                if (
                    incomplete is None
                    or drained.status is StageStatus.FAILED
                    and incomplete.status is StageStatus.BLOCKED
                ):
                    incomplete = drained
        if set(outcomes) != seen_candidate_ids or set(progress) - seen_batch_ids:
            raise ValueError("CANDIDATE_BATCH_PROGRESS_INVALID")
        if incomplete is not None:
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status=(
                    "FAILED" if incomplete.status is StageStatus.FAILED else "BLOCKED"
                ),
                current_stage=incomplete.current_stage,
                error_code=incomplete.error_code,
                child_hypothesis_id=incomplete.hypothesis_id,
                child_attempt_id=incomplete.attempt_id,
            )
        surface_outcome = await self._run_targeted_surface_exploration(
            run,
            identity,
            static,
            scope,
            artifacts,
            ast_summary,
            surface_index,
            surface_index_ref,
            checkpoint,
            attempted_in_turn=attempted_in_turn,
            turn_id=turn_id,
        )
        if surface_outcome is not None:
            return surface_outcome
        chain_outcome = await self._run_final_chaining_pool(
            run,
            identity,
            static,
            attempted_in_turn=attempted_in_turn,
            turn_id=turn_id,
        )
        if chain_outcome is not None:
            return chain_outcome
        return self._finish_candidate_batches_v2(
            run,
            identity,
            static,
            scope,
            artifacts,
            ast_summary,
            surface_index,
            surface_index_ref,
            checkpoint,
        )

    def _finish_candidate_batches_v2(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
        artifacts: SimpleArtifactRepository,
        ast_summary: dict[str, object],
        index: SurfaceIndex,
        index_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
    ) -> SimpleAnalysisOutcome:
        """Certify only known finished work; retain measured coverage gaps."""

        after_id: str | None = None
        while True:
            candidates = self._store.list_candidates(
                identity,
                scope,
                status=("INCLUDE", "UNDECIDED"),
                after_id=after_id,
                limit=64,
            )
            if not candidates:
                break
            for candidate in candidates:
                after_id = candidate.candidate_id
                if candidate.deep_status == "NO_HYPOTHESIS":
                    continue
                linked: list[str] = []
                link_after: str | None = None
                while True:
                    ids = self._store.list_candidate_hypothesis_ids(
                        identity,
                        scope,
                        candidate.candidate_id,
                        after_id=link_after,
                        limit=64,
                    )
                    if not ids:
                        break
                    linked.extend(ids)
                    link_after = ids[-1]
                if linked and all(
                    self._candidate_hypothesis_terminal(identity, item)
                    for item in linked
                ):
                    self._store.save_candidate_deep_status(
                        identity, scope, candidate.candidate_id, "COMPLETE"
                    )
        counts = self._store.candidate_counts(identity, scope)
        deep = self._store.candidate_deep_counts(identity, scope)
        pending = self._store.list_incomplete_hypotheses(identity, limit=1)
        if (
            counts.get("PENDING", 0)
            or counts.get("ERROR", 0)
            or any(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
            or pending
        ):
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                "CANDIDATE_WORK_INCOMPLETE",
                current_checkpoint=checkpoint,
            )
        coverage = self._final_surface_coverage(
            identity, static, scope, artifacts, ast_summary, index, index_ref
        )
        coverage_ref = artifacts.put_json(coverage.to_json())
        handler = self._runner_factory(self._store, identity, static).handlers.get(
            SimpleStage.CHAINING_DONE
        )
        if handler is None or not callable(getattr(handler, "pool_fingerprint", None)):
            raise ValueError("CHAINING_POOL_HANDLER_UNAVAILABLE")
        chaining = cast(SimpleChainingStage, handler)
        fingerprint = chaining.pool_fingerprint(identity)
        plan = chaining.plan_chaining_for_pool(identity, fingerprint)
        saved = self._store.list_chaining_pool_batches(identity, fingerprint)
        if set(saved) != {batch.batch_index for batch in plan} or any(
            saved[batch.batch_index][0] != batch.batch_count for batch in plan
        ):
            raise ValueError("CHAINING_POOL_PROGRESS_INVALID")
        surface_counts = {
            status: sum(
                surface.coverage_status == status for surface in coverage.surfaces
            )
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        terminal_status: Literal["COMPLETE", "PARTIAL"] = (
            "COMPLETE"
            if run.static_disposition == "FULL" and coverage.complete
            else "PARTIAL"
        )
        terminal = CandidateTerminal(
            status=terminal_status,
            bundle_hash=static.static_bundle_ref.content_hash,
            scope_fingerprint=scope,
            decision_counts=counts,
            deep_counts=deep,
            hypothesis_count=self._store.hypothesis_count(identity),
            surface_index_hash=index_ref.content_hash,
            surface_coverage_hash=coverage_ref.content_hash,
            surface_counts=surface_counts,
            producer_finished=True,
            chaining_pool_fingerprint=fingerprint,
            chaining_batch_count=len(plan),
            pending_child_count=0,
        )
        completed_run = run.model_copy(update={"candidate_terminal": terminal})
        expected_outputs = (index_ref, coverage_ref)
        if (
            checkpoint.status is StageStatus.SUCCEEDED
            and checkpoint.output_refs != expected_outputs
        ):
            # A repaired child can change final surface coverage while the
            # earlier producer checkpoint remains successful. Re-certify its
            # exact outputs before publishing the new terminal marker.
            checkpoint = self._store.mark_running(
                identity,
                SimpleStage.HYPOTHESIS_DONE,
                checkpoint.input_refs,
                attempt_id=uuid4().hex,
            )
        if checkpoint.status is not StageStatus.SUCCEEDED:
            self._store.complete(
                checkpoint,
                self._stage_result(*expected_outputs),
            )
        self._store.save_analysis_run(completed_run)
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status=terminal_status,
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    def _final_surface_coverage(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
        artifacts: SimpleArtifactRepository,
        ast_summary: dict[str, object],
        index: SurfaceIndex,
        index_ref: StoredDataRef,
    ) -> SurfaceCoverage:
        """Recheck every context part and its downstream child before coverage."""

        reviews = list(
            self._candidate_surface_reviews(identity, scope, index, artifacts)
        )
        initial = evaluate_surface_coverage(index, reviews)
        progress = self._store.list_surface_exploration_progress(identity, scope)
        contexts_by_surface: dict[str, list[SurfaceContext]] = {}
        expected: set[tuple[str, str]] = set()
        for context in iter_uncovered_surface_contexts(
            index,
            initial,
            64 * 1024,
            artifacts=artifacts,
            ast_summary=ast_summary,
            workspace=static.workspace_path,
        ):
            contexts_by_surface.setdefault(context.surface_id, []).append(context)
            expected.add((context.surface_id, context.context_id))
        effective_contexts: dict[str, list[SurfaceContext]] = {}
        surfaces_by_id = {surface.surface_id: surface for surface in index.surfaces}
        for surface_id, first_contexts in contexts_by_surface.items():
            effective_contexts[surface_id] = first_contexts
            if self._surface_expansion_needed(
                index, first_contexts, progress, artifacts=artifacts
            ):
                second = list(
                    expanded_surface_contexts(
                        index,
                        surfaces_by_id[surface_id],
                        artifacts=artifacts,
                        ast_summary=ast_summary,
                        workspace=static.workspace_path,
                    )
                )
                expected.update((surface_id, item.context_id) for item in second)
                contexts_by_surface[surface_id] = [*first_contexts, *second]
                effective_contexts[surface_id] = second
        prior_covered = {
            surface.surface_id
            for surface in initial.surfaces
            if surface.coverage_status == "COVERED"
        }
        if any(key not in expected and key[0] not in prior_covered for key in progress):
            raise ValueError("SURFACE_EXPLORATION_SCOPE_CHANGED")
        for surface_id, contexts in contexts_by_surface.items():
            records = [progress.get((surface_id, item.context_id)) for item in contexts]
            if any(record is None for record in records):
                raise ValueError("SURFACE_EXPLORATION_PROGRESS_INCOMPLETE")
            parts: set[str] = set()
            locations: set[str] = set()
            evidence_refs: list[StoredDataRef] = []
            complete = True
            effective_ids = {
                context.context_id for context in effective_contexts[surface_id]
            }
            for context, record in zip(contexts, records, strict=True):
                assert record is not None
                if (
                    record.static_bundle_hash != static.static_bundle_ref.content_hash
                    or record.index_hash != index_ref.content_hash
                    or record.context_hash != context.context_hash
                    or record.source_sha256 != context.source_sha256
                    or record.proposal_version
                    != self._surface_context_version(artifacts, context)
                ):
                    raise ValueError("SURFACE_EXPLORATION_SCOPE_CHANGED")
                self._surface_result_valid(
                    artifacts,
                    context,
                    record.status,
                    record.result_ref,
                    static.static_bundle_ref.content_hash,
                    analysis_id=identity.analysis_id,
                    expected_seed_ids=record.hypothesis_ids,
                )
                value = json.loads(artifacts.read(record.result_ref))
                if context.context_id in effective_ids:
                    parts.update(value["reviewed_parts"])
                    locations.update(value["evidence_locations"])
                    evidence_refs.append(record.result_ref)
                    if record.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS":
                        complete = False
                for hypothesis_id in record.hypothesis_ids:
                    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                    initial_checkpoint = self._store.get(
                        child, SimpleStage.VERIFICATION_INITIAL_DONE
                    )
                    poc_checkpoint = self._store.get(
                        child, SimpleStage.POC_EXECUTION_DONE
                    )
                    final = self._store.get(child, SimpleStage.VERIFICATION_FINAL_DONE)
                    if not self._candidate_hypothesis_terminal(identity, hypothesis_id):
                        complete = False
                        continue
                    if (
                        initial_checkpoint is not None
                        and self._store.verified_terminal_initial_outcome(
                            initial_checkpoint
                        )
                        is not None
                    ):
                        # An environment/prerequisite HOLD ends this child
                        # safely, but it did not verify the attack surface.
                        complete = False
                        output_refs = initial_checkpoint.output_refs
                    elif (
                        poc_checkpoint is not None
                        and self._store.verified_terminal_poc_outcome(poc_checkpoint)
                        is not None
                    ):
                        complete = False
                        output_refs = poc_checkpoint.output_refs
                    elif (
                        final is not None
                        and final.status is StageStatus.SUCCEEDED
                        and final.output_refs
                    ):
                        output_refs = final.output_refs
                    else:
                        complete = False
                        continue
                    for ref in output_refs:
                        artifacts.read(ref)
                    if context.context_id in effective_ids:
                        evidence_refs.extend(output_refs)
            reviews.append(
                SurfaceReview(
                    surface_id=surface_id,
                    candidate_id=None,
                    hypothesis_id=None,
                    verification_status="COMPLETE" if complete else "PENDING",
                    reviewed_parts=frozenset(
                        cast(
                            set[
                                Literal[
                                    "ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"
                                ]
                            ],
                            parts,
                        )
                    ),
                    evidence_locations=tuple(sorted(locations)),
                    evidence_refs=tuple(dict.fromkeys(evidence_refs)),
                )
            )
        return evaluate_surface_coverage(index, reviews)

    @staticmethod
    def _surface_context_version(
        artifacts: SimpleArtifactRepository, context: SurfaceContext
    ) -> int:
        payload = json.loads(artifacts.read(context.context_ref))
        if not isinstance(payload, dict):
            raise ValueError("SURFACE_EXPLORATION_CONTEXT_INVALID")
        kind = payload.get("kind")
        if kind == "simple_surface_context_v1":
            return 1
        if kind == "simple_surface_context_v2":
            return 2
        raise ValueError("SURFACE_EXPLORATION_CONTEXT_INVALID")

    @staticmethod
    def _surface_expansion_needed(
        index: SurfaceIndex,
        contexts: Sequence[SurfaceContext],
        progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
        *,
        artifacts: SimpleArtifactRepository | None = None,
    ) -> bool:
        if index.index_version != 2 or not contexts:
            return False
        needs_more_evidence = False
        required_parts = {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
        for context in contexts:
            record = progress.get((context.surface_id, context.context_id))
            if record is None:
                continue
            if record.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS":
                needs_more_evidence = True
                break
            if record.status != "HYPOTHESES" or artifacts is None:
                continue
            try:
                result = json.loads(artifacts.read(record.result_ref))
                reviewed_parts = result.get("reviewed_parts")
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(reviewed_parts, list) or not required_parts <= set(
                reviewed_parts
            ):
                needs_more_evidence = True
                break
        if not needs_more_evidence:
            return False
        return any(
            item.source_unavailable_reason is None
            and (
                (item.omitted_source_line_count or 0) > 0
                or (item.omitted_ast_fact_count or 0) > 0
            )
            for item in contexts
        )

    async def _run_final_chaining_pool(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        *,
        attempted_in_turn: set[str],
        turn_id: str,
    ) -> SimpleAnalysisOutcome | None:
        """Replay exact pool batches, then verify newly materialized chain children."""

        handler = self._runner_factory(self._store, identity, static).handlers.get(
            SimpleStage.CHAINING_DONE
        )
        if handler is None or not all(
            callable(getattr(handler, name, None))
            for name in (
                "admitted_primitive_refs",
                "pool_fingerprint",
                "plan_chaining_for_pool",
                "finalize_chaining_batch",
            )
        ):
            raise ValueError("CHAINING_POOL_HANDLER_UNAVAILABLE")
        chaining = cast(SimpleChainingStage, handler)
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        checkpoint = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        while True:
            admitted = chaining.admitted_primitive_refs(identity)
            fingerprint = chaining.pool_fingerprint(identity)
            plan = chaining.plan_chaining_for_pool(identity, fingerprint)
            saved = self._store.list_chaining_pool_batches(identity, fingerprint)
            if set(saved) - {batch.batch_index for batch in plan}:
                raise ValueError("CHAINING_POOL_PROGRESS_INVALID")
            for batch in plan:
                previous = saved.get(batch.batch_index)
                if previous is None:
                    try:
                        result = await chaining.finalize_chaining_batch(identity, batch)
                    except (StageBlocked, StageFailed) as error:
                        return self._candidate_bootstrap_failure(
                            run,
                            identity,
                            static,
                            error.failure.code,
                            paused=error.failure.code in BUDGET_PAUSE_CODES,
                            evidence_refs=error.failure.evidence_refs,
                            current_checkpoint=checkpoint,
                        )
                    if len(result.output_refs) != 1:
                        raise ValueError("CHAINING_POOL_RESULT_INVALID")
                    result_ref = result.output_refs[0]
                    self._chaining_pool_result_valid(
                        artifacts, identity, batch, admitted, result_ref
                    )
                    self._store.save_chaining_pool_batch(
                        identity,
                        fingerprint,
                        batch.batch_index,
                        batch.batch_count,
                        result_ref,
                    )
                else:
                    batch_count, result_ref = previous
                    if batch_count != batch.batch_count:
                        raise ValueError("CHAINING_POOL_PROGRESS_INVALID")
                    self._chaining_pool_result_valid(
                        artifacts, identity, batch, admitted, result_ref
                    )
                synthetic = StageCheckpoint(
                    identity=identity,
                    stage=SimpleStage.CHAINING_DONE,
                    status=StageStatus.SUCCEEDED,
                    input_refs=(),
                    input_hash=input_reference_hash(()),
                    output_refs=(result_ref,),
                )
                try:
                    self._register_chaining_result(
                        run, identity, static, synthetic, result_ref
                    )
                except ChainingEvidenceInvalid as error:
                    raise ValueError("CHAINING_POOL_RESULT_INVALID") from error
                drained = await self._drain_candidate_children(
                    run,
                    identity,
                    static,
                    attempted_in_turn=attempted_in_turn,
                    turn_id=turn_id,
                    max_runnable=self._max_pending_candidate_children,
                )
                if drained is not None:
                    return SimpleAnalysisOutcome(
                        identity=identity,
                        display_analysis_id=run.display_analysis_id,
                        status=(
                            "PAUSED"
                            if drained.error_code in BUDGET_PAUSE_CODES
                            else "FAILED"
                            if drained.status is StageStatus.FAILED
                            else "BLOCKED"
                        ),
                        current_stage=drained.current_stage,
                        error_code=drained.error_code,
                        child_hypothesis_id=drained.hypothesis_id,
                        child_attempt_id=drained.attempt_id,
                    )
                if chaining.pool_fingerprint(identity) != fingerprint:
                    break
            if self._store.list_incomplete_hypotheses(identity, limit=1):
                return self._candidate_bootstrap_failure(
                    run,
                    identity,
                    static,
                    "CHAINING_CHILD_WORK_INCOMPLETE",
                    paused=True,
                    current_checkpoint=checkpoint,
                )
            if chaining.pool_fingerprint(identity) == fingerprint:
                return None

    @staticmethod
    def _chaining_pool_result_valid(
        artifacts: SimpleArtifactRepository,
        identity: CheckpointIdentity,
        batch: ChainingPoolBatch,
        admitted: tuple[StoredDataRef, ...],
        result_ref: StoredDataRef,
    ) -> None:
        try:
            value = json.loads(artifacts.read(result_ref))
            considered = tuple(
                StoredDataRef.model_validate(item)
                for item in value["considered_primitive_refs"]
            )
            unconsidered = tuple(
                StoredDataRef.model_validate(item)
                for item in value["unconsidered_primitive_refs"]
            )
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("CHAINING_POOL_RESULT_INVALID") from error
        if (
            value.get("kind") != "simple_chaining_result"
            or value.get("analysis_id") != identity.analysis_id
            or value.get("source_hypothesis_id") is not None
            or value.get("pool_fingerprint") != batch.pool_fingerprint
            or type(value.get("batch_index")) is not int
            or value["batch_index"] != batch.batch_index
            or type(value.get("batch_count")) is not int
            or value["batch_count"] != batch.batch_count
            or considered != batch.considered_primitive_refs
            or unconsidered != batch.unconsidered_primitive_refs
            or len(set(considered + unconsidered)) != len(admitted)
            or set(considered + unconsidered) != set(admitted)
        ):
            raise ValueError("CHAINING_POOL_RESULT_INVALID")
        children = value.get("children")
        if not isinstance(children, list) or len(children) >= 4:
            raise ValueError("CHAINING_POOL_RESULT_INVALID")
        if value.get("status") != (
            "MATERIAL_CHILD" if children else "NO_MATERIAL_CHILD"
        ):
            raise ValueError("CHAINING_POOL_RESULT_INVALID")
        try:
            validated = validated_chaining_children(
                artifacts,
                considered,
                children,
                pair_partition=(
                    frozenset(ref.content_hash for ref in batch.left_primitive_refs),
                    frozenset(ref.content_hash for ref in batch.right_primitive_refs),
                ),
            )
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("CHAINING_POOL_RESULT_INVALID") from error
        if canonical_bytes(children) != canonical_bytes(validated):
            raise ValueError("CHAINING_POOL_RESULT_INVALID")

    def _candidate_surface_reviews(
        self,
        identity: CheckpointIdentity,
        scope: str,
        index: SurfaceIndex,
        artifacts: SimpleArtifactRepository,
    ) -> tuple[SurfaceReview, ...]:
        """Only a qualified, terminal candidate child may cover its linked site."""

        reviews: list[SurfaceReview] = []
        by_candidate: dict[str, list[str]] = {}
        for surface in index.surfaces:
            for candidate_id in surface.linked_candidate_ids:
                by_candidate.setdefault(candidate_id, []).append(surface.surface_id)
        surfaces = {surface.surface_id: surface for surface in index.surfaces}
        for candidate_id, surface_ids in by_candidate.items():
            after_id: str | None = None
            while True:
                ids = self._store.list_candidate_hypothesis_ids(
                    identity, scope, candidate_id, after_id=after_id, limit=64
                )
                if not ids:
                    break
                after_id = ids[-1]
                for hypothesis_id in ids:
                    if not self._candidate_hypothesis_terminal(identity, hypothesis_id):
                        continue
                    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                    pro_con = self._store.get(child, SimpleStage.PRO_CON_DONE)
                    final = self._store.get(child, SimpleStage.VERIFICATION_FINAL_DONE)
                    if (
                        pro_con is None
                        or not pro_con.input_refs
                        or final is None
                        or final.status is not StageStatus.SUCCEEDED
                        or not final.output_refs
                    ):
                        continue
                    proposal_ref = pro_con.input_refs[0]
                    proposal = json.loads(artifacts.read_prompt_proposal(proposal_ref))
                    if (
                        not isinstance(proposal, dict)
                        or proposal.get("kind") != "simple_hypothesis_proposal"
                        or proposal.get("candidate_id") != candidate_id
                        or proposal.get("hypothesis_id") != hypothesis_id
                    ):
                        raise ValueError("SURFACE_CANDIDATE_REVIEW_INVALID")
                    qualification = proposal.get("qualification")
                    described = proposal.get("proposal")
                    if not isinstance(qualification, dict) or not isinstance(
                        described, dict
                    ):
                        continue
                    locations = qualification.get("evidence_locations")
                    code_locations = described.get("code_locations")
                    if (
                        qualification.get("attacker_control") not in {"YES", "POSSIBLE"}
                        or qualification.get("sensitive_operation") != "YES"
                        or qualification.get("reachability") not in {"YES", "POSSIBLE"}
                        or not isinstance(qualification.get("trust_boundary"), str)
                        or not qualification["trust_boundary"].strip()
                        or not isinstance(locations, list)
                        or not isinstance(code_locations, list)
                        or not all(isinstance(item, str) for item in locations)
                        or not all(isinstance(item, str) for item in code_locations)
                    ):
                        continue
                    for ref in final.output_refs:
                        artifacts.read(ref)
                    evidence_locations = tuple(
                        dict.fromkeys((*locations, *code_locations))
                    )
                    for surface_id in surface_ids:
                        surface = surfaces[surface_id]
                        if f"{surface.path}:{surface.line}" not in evidence_locations:
                            continue
                        reviews.append(
                            SurfaceReview(
                                surface_id=surface_id,
                                candidate_id=candidate_id,
                                hypothesis_id=hypothesis_id,
                                verification_status="COMPLETE",
                                # The proposal names a linked location, but
                                # does not assign distinct evidence to the
                                # entry, operation, and trust boundary. A
                                # terminal child alone cannot certify all
                                # three coverage parts.
                                reviewed_parts=frozenset(),
                                evidence_locations=evidence_locations,
                                evidence_refs=(proposal_ref, *final.output_refs),
                            )
                        )
        return tuple(reviews)

    async def _run_targeted_surface_exploration(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
        artifacts: SimpleArtifactRepository,
        ast_summary: dict[str, object],
        index: SurfaceIndex,
        index_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
        *,
        attempted_in_turn: set[str],
        turn_id: str,
    ) -> SimpleAnalysisOutcome | None:
        propose_surface = getattr(self._candidate_hypotheses, "propose_surface", None)
        if not callable(propose_surface):
            return self._candidate_bootstrap_failure(
                run,
                identity,
                static,
                "HYPOTHESIS_SURFACE_UNAVAILABLE",
                current_checkpoint=checkpoint,
            )
        reviews = self._candidate_surface_reviews(identity, scope, index, artifacts)
        coverage = evaluate_surface_coverage(index, reviews)
        progress = self._store.list_surface_exploration_progress(identity, scope)
        seen_contexts: set[tuple[str, str]] = set()
        try:
            first_contexts = iter_uncovered_surface_contexts(
                index,
                coverage,
                64 * 1024,
                artifacts=artifacts,
                ast_summary=ast_summary,
                workspace=static.workspace_path,
            )
            by_surface: dict[str, list[SurfaceContext]] = {}
            for context in first_contexts:
                by_surface.setdefault(context.surface_id, []).append(context)

            def contexts_to_review() -> Iterator[SurfaceContext]:
                surfaces = {surface.surface_id: surface for surface in index.surfaces}
                for surface_id, contexts in by_surface.items():
                    yield from contexts
                    updated = self._store.list_surface_exploration_progress(
                        identity, scope
                    )
                    if self._surface_expansion_needed(
                        index, contexts, updated, artifacts=artifacts
                    ):
                        yield from expanded_surface_contexts(
                            index,
                            surfaces[surface_id],
                            artifacts=artifacts,
                            ast_summary=ast_summary,
                            workspace=static.workspace_path,
                        )

            contexts = contexts_to_review()
            for context in contexts:
                key = (context.surface_id, context.context_id)
                if key in seen_contexts:
                    raise ValueError("SURFACE_CONTEXT_DUPLICATE")
                seen_contexts.add(key)
                prior = progress.get(key)
                if prior is not None:
                    if (
                        prior.static_bundle_hash
                        != static.static_bundle_ref.content_hash
                        or prior.index_hash != index_ref.content_hash
                        or prior.context_hash != context.context_hash
                        or prior.source_sha256 != context.source_sha256
                        or prior.proposal_version
                        != self._surface_context_version(artifacts, context)
                    ):
                        raise ValueError("SURFACE_EXPLORATION_SCOPE_CHANGED")
                    self._surface_result_valid(
                        artifacts,
                        context,
                        prior.status,
                        prior.result_ref,
                        static.static_bundle_ref.content_hash,
                        analysis_id=identity.analysis_id,
                        expected_seed_ids=prior.hypothesis_ids,
                    )
                    for hypothesis_id in prior.hypothesis_ids:
                        child = identity.model_copy(
                            update={"hypothesis_id": hypothesis_id}
                        )
                        saved = self._store.require(child, SimpleStage.PRO_CON_DONE)
                        if not saved.input_refs:
                            raise ValueError("SURFACE_EXPLORATION_PROPOSAL_INVALID")
                        self._surface_proposal_valid(
                            artifacts,
                            identity,
                            context,
                            static,
                            prior.result_ref,
                            hypothesis_id,
                            saved.input_refs[0],
                        )
                else:
                    pending_count = len(
                        self._store.list_incomplete_hypotheses(
                            identity, limit=self._max_pending_candidate_children + 1
                        )
                    )
                    if pending_count + 4 > self._max_pending_candidate_children:
                        return self._candidate_bootstrap_failure(
                            run,
                            identity,
                            static,
                            "CANDIDATE_BACKPRESSURE_BLOCKED",
                            current_checkpoint=checkpoint,
                        )
                    result = await propose_surface(identity, static, context)
                    if isinstance(result, StageFailure):
                        return self._candidate_bootstrap_failure(
                            run,
                            identity,
                            static,
                            (
                                "HYPOTHESIS_SURFACE_PROVIDER_FAILED"
                                if result.code == "FAILED"
                                else result.code
                            ),
                            paused=result.code in BUDGET_PAUSE_CODES,
                            evidence_refs=result.evidence_refs,
                            current_checkpoint=checkpoint,
                        )
                    self._surface_result_valid(
                        artifacts,
                        context,
                        result.status,
                        result.result_ref,
                        static.static_bundle_ref.content_hash,
                        analysis_id=identity.analysis_id,
                        expected_seed_ids=tuple(
                            seed.hypothesis_id for seed in result.seeds
                        ),
                        expected_reviewed_parts=result.reviewed_parts,
                        expected_locations=result.evidence_locations,
                    )
                    registrations: list[tuple[str, StoredDataRef, StageCheckpoint]] = []
                    for seed in result.seeds:
                        self._surface_proposal_valid(
                            artifacts,
                            identity,
                            context,
                            static,
                            result.result_ref,
                            seed.hypothesis_id,
                            seed.proposal_ref,
                        )
                        artifacts.prompt_context_strict(
                            (seed.proposal_ref, context.context_ref)
                        )
                        inputs = (seed.proposal_ref, context.context_ref)
                        registrations.append(
                            (
                                seed.hypothesis_id,
                                seed.proposal_ref,
                                StageCheckpoint(
                                    identity=identity.model_copy(
                                        update={"hypothesis_id": seed.hypothesis_id}
                                    ),
                                    stage=SimpleStage.PRO_CON_DONE,
                                    status=StageStatus.PENDING,
                                    input_refs=inputs,
                                    input_hash=input_reference_hash(inputs),
                                ),
                            )
                        )
                    self._store.commit_surface_exploration(
                        identity,
                        scope,
                        context.surface_id,
                        context.context_id,
                        static_bundle_hash=static.static_bundle_ref.content_hash,
                        index_hash=index_ref.content_hash,
                        context_hash=context.context_hash,
                        source_sha256=context.source_sha256,
                        status=result.status,
                        result_ref=result.result_ref,
                        registrations=registrations,
                        proposal_version=self._surface_context_version(
                            artifacts, context
                        ),
                    )
                drained = await self._drain_candidate_children(
                    run,
                    identity,
                    static,
                    attempted_in_turn=attempted_in_turn,
                    turn_id=turn_id,
                    max_runnable=self._max_pending_candidate_children,
                )
                if drained is not None:
                    return SimpleAnalysisOutcome(
                        identity=identity,
                        display_analysis_id=run.display_analysis_id,
                        status=(
                            "PAUSED"
                            if drained.error_code in BUDGET_PAUSE_CODES
                            else "FAILED"
                            if drained.status is StageStatus.FAILED
                            else "BLOCKED"
                        ),
                        current_stage=drained.current_stage,
                        error_code=drained.error_code,
                        child_hypothesis_id=drained.hypothesis_id,
                        child_attempt_id=drained.attempt_id,
                    )
        except SurfaceContextOverflow as error:
            return self._candidate_bootstrap_failure(
                run, identity, static, str(error), current_checkpoint=checkpoint
            )
        if set(progress) - seen_contexts:
            covered_ids = {
                surface.surface_id
                for surface in coverage.surfaces
                if surface.coverage_status == "COVERED"
            }
            if any(
                surface_id not in covered_ids
                for surface_id, _context_id in set(progress) - seen_contexts
            ):
                raise ValueError("SURFACE_EXPLORATION_SCOPE_CHANGED")
        return None

    @staticmethod
    def _surface_proposal_valid(
        artifacts: SimpleArtifactRepository,
        identity: CheckpointIdentity,
        context: SurfaceContext,
        static: StaticBootstrapResult,
        result_ref: StoredDataRef,
        hypothesis_id: str,
        proposal_ref: StoredDataRef,
    ) -> None:
        proposal = json.loads(artifacts.read_prompt_proposal(proposal_ref))
        if not isinstance(proposal, dict):
            raise ValueError("SURFACE_EXPLORATION_PROPOSAL_INVALID")
        try:
            saved_static = StoredDataRef.model_validate(proposal["static_bundle_ref"])
            saved_context = StoredDataRef.model_validate(
                proposal["surface_context_ref"]
            )
            saved_result = StoredDataRef.model_validate(proposal["surface_result_ref"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_EXPLORATION_PROPOSAL_INVALID") from error
        if (
            proposal.get("kind") != "simple_hypothesis_proposal"
            or proposal.get("analysis_id") != identity.analysis_id
            or proposal.get("hypothesis_id") != hypothesis_id
            or proposal.get("surface_id") != context.surface_id
            or proposal.get("context_id") != context.context_id
            or proposal.get("part_index") != context.part_index
            or proposal.get("part_count") != context.part_count
            or saved_static != static.static_bundle_ref
            or saved_context != context.context_ref
            or saved_result != result_ref
            or not isinstance(proposal.get("proposal"), dict)
            or not isinstance(proposal.get("qualification"), dict)
        ):
            raise ValueError("SURFACE_EXPLORATION_PROPOSAL_INVALID")

    @staticmethod
    def _surface_result_valid(
        artifacts: SimpleArtifactRepository,
        context: SurfaceContext,
        status: str,
        result_ref: StoredDataRef,
        static_bundle_hash: str,
        *,
        analysis_id: str,
        expected_seed_ids: tuple[str, ...],
        expected_reviewed_parts: frozenset[str] | None = None,
        expected_locations: tuple[str, ...] | None = None,
    ) -> None:
        value = json.loads(artifacts.read(result_ref))
        context_payload = json.loads(artifacts.read(context.context_ref))
        expected_kind = (
            "simple_surface_hypothesis_result_v2"
            if isinstance(context_payload, dict)
            and context_payload.get("kind") == "simple_surface_context_v2"
            else "simple_surface_hypothesis_result_v1"
        )
        seed_ids = value.get("seed_ids") if isinstance(value, dict) else None
        parts = value.get("reviewed_parts") if isinstance(value, dict) else None
        locations = value.get("evidence_locations") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or value.get("kind") != expected_kind
            or value.get("analysis_id") != analysis_id
            or value.get("surface_id") != context.surface_id
            or value.get("context_id") != context.context_id
            or value.get("part_index") != context.part_index
            or value.get("part_count") != context.part_count
            or value.get("context_hash") != context.context_hash
            or value.get("static_bundle_hash") != static_bundle_hash
            or value.get("status") != status
            or status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or not isinstance(parts, list)
            or not all(
                item in {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
                for item in parts
            )
            or not isinstance(locations, list)
            or not all(isinstance(item, str) for item in locations)
            or not isinstance(seed_ids, list)
            or not all(isinstance(item, str) and item for item in seed_ids)
            or len(seed_ids) != len(set(seed_ids))
            or tuple(seed_ids) != expected_seed_ids
            or (status == "HYPOTHESES") != bool(seed_ids)
            or (
                expected_reviewed_parts is not None
                and set(parts) != expected_reviewed_parts
            )
            or (
                expected_locations is not None
                and tuple(locations) != expected_locations
            )
        ):
            raise ValueError("SURFACE_EXPLORATION_RESULT_INVALID")

    async def _run_free_candidate_exploration(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        artifacts: SimpleArtifactRepository,
    ) -> StageFailure | None:
        """Replay finished source pages before requesting only new pages."""

        propose_page = getattr(self._hypotheses, "propose_page", None)
        if not callable(propose_page):
            return StageFailure(
                code="HYPOTHESIS_PAGE_UNAVAILABLE",
                retryable=False,
                safe_message="The configured hypothesis Agent cannot page source code",
            )
        bundle_hash = static.static_bundle_ref.content_hash
        progress = self._store.survey_progress(identity.analysis_id, bundle_hash)
        done_key = "__candidate_free_done__"
        if done_key in progress:
            try:
                self._candidate_free_done_valid(identity, static, progress)
            except (OSError, ValueError, TypeError, sqlite3.Error):
                return StageFailure(
                    code="HYPOTHESIS_PAGE_CHECKPOINT_INVALID",
                    retryable=False,
                    safe_message="Stored free exploration completion is invalid",
                    evidence_refs=(progress[done_key],),
                )
            return None
        cursor: str | None = None
        page_index = 0
        while True:
            key = f"__candidate_free_page_{page_index:08d}__"
            existing = progress.get(key)
            if existing is not None:
                try:
                    page_record = json.loads(artifacts.read(existing))
                    if (
                        not isinstance(page_record, dict)
                        or page_record.get("kind")
                        != "simple_candidate_free_exploration_page"
                        or page_record.get("analysis_id") != identity.analysis_id
                        or page_record.get("static_bundle_hash") != bundle_hash
                        or page_record.get("cursor") != cursor
                        or not isinstance(page_record.get("seeds"), list)
                    ):
                        raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
                    next_cursor = page_record.get("next_cursor")
                    seeds = tuple(
                        HypothesisSeed.model_validate(item)
                        for item in page_record["seeds"]
                    )
                except (OSError, ValueError, TypeError, KeyError):
                    return StageFailure(
                        code="HYPOTHESIS_PAGE_CHECKPOINT_INVALID",
                        retryable=False,
                        safe_message="Stored free exploration page is invalid",
                        evidence_refs=(existing,),
                    )
            else:
                first_failure_refs: tuple[StoredDataRef, ...] = ()
                page_result = await propose_page(identity, static, after_cursor=cursor)
                if (
                    isinstance(page_result, StageFailure)
                    and page_result.retryable
                    and page_result.code in {"FAILED", "TIMED_OUT"}
                ):
                    first_failure_refs = page_result.evidence_refs
                    page_result = await propose_page(
                        identity, static, after_cursor=cursor
                    )
                if isinstance(page_result, StageFailure):
                    return page_result.model_copy(
                        update={
                            "evidence_refs": tuple(
                                dict.fromkeys(
                                    (*first_failure_refs, *page_result.evidence_refs)
                                )
                            )
                        }
                    )
                seeds, next_cursor = page_result
                page_record = {
                    "kind": "simple_candidate_free_exploration_page",
                    "analysis_id": identity.analysis_id,
                    "static_bundle_hash": bundle_hash,
                    "cursor": cursor,
                    "next_cursor": next_cursor,
                    "seeds": [seed.model_dump(mode="json") for seed in seeds],
                    **(
                        {
                            "retry_failure_refs": [
                                ref.model_dump(mode="json")
                                for ref in first_failure_refs
                            ]
                        }
                        if first_failure_refs
                        else {}
                    ),
                }
                marker = artifacts.put_json(page_record)
                self._store.save_survey_progress(
                    identity.analysis_id, bundle_hash, key, marker
                )
                progress[key] = marker
            if next_cursor is not None and (
                not isinstance(next_cursor, str)
                or not next_cursor
                or next_cursor == cursor
            ):
                return StageFailure(
                    code="HYPOTHESIS_PAGE_CURSOR_INVALID",
                    retryable=False,
                    safe_message="Free exploration page did not advance",
                )
            for seed in seeds:
                try:
                    proposal = json.loads(
                        artifacts.read_prompt_proposal(seed.proposal_ref)
                    )
                    if (
                        not isinstance(proposal, dict)
                        or proposal.get("kind") != "simple_hypothesis_proposal"
                        or proposal.get("hypothesis_id") != seed.hypothesis_id
                    ):
                        raise ValueError("HYPOTHESIS_PAGE_PROPOSAL_INVALID")
                    page_ref = StoredDataRef.model_validate(proposal["page_input_ref"])
                    page_input = json.loads(artifacts.read(page_ref))
                    if (
                        not isinstance(page_input, dict)
                        or page_input.get("kind") != "simple_hypothesis_source_page"
                        or page_input.get("analysis_id") != identity.analysis_id
                        or page_input.get("cursor") != cursor
                    ):
                        raise ValueError("HYPOTHESIS_PAGE_PROPOSAL_INVALID")
                    artifacts.prompt_context_strict((seed.proposal_ref, page_ref))
                except (OSError, ValueError, TypeError, KeyError):
                    return StageFailure(
                        code="HYPOTHESIS_PAGE_PROPOSAL_INVALID",
                        retryable=False,
                        safe_message="Stored free exploration proposal is invalid",
                        evidence_refs=(seed.proposal_ref,),
                    )
                page_static = static.model_copy(update={"static_bundle_ref": page_ref})
                self._register_candidate_seed(identity, page_static, seed)
            if next_cursor is None:
                done = artifacts.put_json(
                    {
                        "kind": "simple_candidate_free_exploration_complete",
                        "analysis_id": identity.analysis_id,
                        "static_bundle_hash": bundle_hash,
                        "page_count": page_index + 1,
                    }
                )
                self._store.save_survey_progress(
                    identity.analysis_id, bundle_hash, done_key, done
                )
                return None
            cursor = next_cursor
            page_index += 1

    def _candidate_free_done_valid(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        progress: Mapping[str, StoredDataRef],
    ) -> bool:
        """Verify a durable completion marker before skipping source pages."""

        marker_ref = progress.get("__candidate_free_done__")
        if marker_ref is None:
            return False
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        marker = json.loads(artifacts.read(marker_ref))
        page_keys = sorted(
            key for key in progress if key.startswith("__candidate_free_page_")
        )
        page_count = marker.get("page_count") if isinstance(marker, dict) else None
        if (
            not isinstance(marker, dict)
            or marker.get("kind") != "simple_candidate_free_exploration_complete"
            or marker.get("analysis_id") != identity.analysis_id
            or marker.get("static_bundle_hash") != static.static_bundle_ref.content_hash
            or type(page_count) is not int
            or page_count < 1
            or len(page_keys) != page_count
            or any(
                key != f"__candidate_free_page_{index:08d}__"
                for index, key in enumerate(page_keys)
            )
        ):
            raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for index, key in enumerate(page_keys):
            page = json.loads(artifacts.read(progress[key]))
            if (
                not isinstance(page, dict)
                or page.get("kind") != "simple_candidate_free_exploration_page"
                or page.get("analysis_id") != identity.analysis_id
                or page.get("static_bundle_hash")
                != static.static_bundle_ref.content_hash
                or page.get("cursor") != cursor
                or not isinstance(page.get("seeds"), list)
            ):
                raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
            for seed in page["seeds"]:
                parsed = HypothesisSeed.model_validate(seed)
                proposal = json.loads(
                    artifacts.read_prompt_proposal(parsed.proposal_ref)
                )
                if (
                    proposal.get("hypothesis_id") != parsed.hypothesis_id
                    or proposal.get("analysis_id") != identity.analysis_id
                    or "page_input_ref" not in proposal
                ):
                    raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
                page_input_ref = StoredDataRef.model_validate(
                    proposal["page_input_ref"]
                )
                page_input = json.loads(artifacts.read(page_input_ref))
                if (
                    not isinstance(page_input, dict)
                    or page_input.get("kind") != "simple_hypothesis_source_page"
                    or page_input.get("analysis_id") != identity.analysis_id
                    or page_input.get("cursor") != cursor
                ):
                    raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
            next_cursor = page.get("next_cursor")
            if index == page_count - 1:
                if next_cursor is not None:
                    raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
            elif (
                not isinstance(next_cursor, str)
                or not next_cursor
                or next_cursor == cursor
                or next_cursor in seen_cursors
            ):
                raise ValueError("HYPOTHESIS_PAGE_CHECKPOINT_INVALID")
            if next_cursor is not None:
                seen_cursors.add(next_cursor)
            cursor = next_cursor
        return True

    def _register_candidate_seed(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        seed: HypothesisSeed,
        *,
        scope: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        child = identity.model_copy(update={"hypothesis_id": seed.hypothesis_id})
        inputs = (seed.proposal_ref, static.static_bundle_ref)
        pending = StageCheckpoint(
            identity=child,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.PENDING,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
        )
        if scope is not None and candidate_id is not None:
            self._store.register_candidate_hypothesis(
                identity,
                scope,
                candidate_id,
                seed.hypothesis_id,
                seed.proposal_ref,
                checkpoint=pending,
            )
        else:
            self._store.register_free_hypothesis(
                identity, seed.hypothesis_id, seed.proposal_ref, pending
            )

    def _candidate_hypothesis_terminal(
        self, identity: CheckpointIdentity, hypothesis_id: str
    ) -> bool:
        child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
        poc = self._store.get(child, SimpleStage.POC_EXECUTION_DONE)
        terminal_poc = self._store.verified_terminal_poc_outcome(poc) is not None
        poc_index = HYPOTHESIS_STAGES.index(SimpleStage.POC_EXECUTION_DONE)
        if any(
            checkpoint is not None
            and checkpoint.stage_version != STAGE_VERSION[stage]
            and (not terminal_poc or HYPOTHESIS_STAGES.index(stage) >= poc_index)
            for stage in HYPOTHESIS_STAGES
            if (checkpoint := self._store.get(child, stage)) is not None
        ):
            return False
        initial = self._store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
        final = self._store.get(child, SimpleStage.VERIFICATION_FINAL_DONE)
        chain = self._store.get(child, SimpleStage.CHAINING_DONE)
        gate = self._store.get(child, SimpleStage.TECH_GATE_DONE)
        report = self._store.get(child, SimpleStage.REPORT_DONE)
        if (
            poc is not None
            and poc.stage_version != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
        ):
            return False
        if (
            final is not None
            and final.stage_version
            != STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE]
        ):
            return False
        return bool(
            self._store.verified_terminal_initial_outcome(initial) is not None
            or terminal_poc
            or final is not None
            and final.status is StageStatus.SUCCEEDED
            and (
                final.verdict == "FALSE"
                or final.verdict == "HOLD"
                and chain is not None
                and chain.status is StageStatus.SUCCEEDED
            )
            or terminal_gate_outcome(gate) is not None
            or report is not None
            and report.status is StageStatus.SUCCEEDED
        )

    def _recover_candidate_chains(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> None:
        # A process can stop after CHAINING_DONE succeeds but before its child
        # is registered. Rebuild the durable queue from successful evidence.
        while True:
            before = self._store.hypothesis_count(identity)
            after_id: str | None = None
            while True:
                ids = self._store.list_hypotheses(identity, after_id=after_id, limit=64)
                if not ids:
                    break
                for hypothesis_id in ids:
                    after_id = hypothesis_id
                    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                    chain = self._store.get(child, SimpleStage.CHAINING_DONE)
                    if chain is not None and chain.status is StageStatus.SUCCEEDED:
                        self._register_chain_children(run, child, static)
            if self._store.hypothesis_count(identity) == before:
                return

    async def _run_candidate_hypotheses(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        scope: str,
    ) -> SimpleAnalysisOutcome:
        latest_stage = SimpleStage.HYPOTHESIS_DONE
        incomplete: RunOutcome | None = None
        self._recover_candidate_chains(run, identity, static)
        self._invalidate_stale_report_coverage(run, identity)
        attempted: set[str] = set()
        while True:
            after_id: str | None = None
            made_progress = False
            while True:
                ids = self._store.list_incomplete_hypotheses(
                    identity, after_id=after_id, limit=32
                )
                if not ids:
                    break
                for hypothesis_id in ids:
                    after_id = hypothesis_id
                    if hypothesis_id in attempted:
                        continue
                    attempted.add(hypothesis_id)
                    made_progress = True
                    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
                    outcome = await self._runner_factory(
                        self._store,
                        child,
                        static,
                    ).resume_hypothesis(child)
                    outcome = outcome.model_copy(
                        update={"hypothesis_id": hypothesis_id}
                    )
                    latest_stage = outcome.current_stage
                    if outcome.status in {StageStatus.BLOCKED, StageStatus.FAILED}:
                        if outcome.error_code in BUDGET_PAUSE_CODES:
                            return SimpleAnalysisOutcome(
                                identity=identity,
                                display_analysis_id=run.display_analysis_id,
                                status="PAUSED",
                                current_stage=latest_stage,
                                error_code=outcome.error_code,
                                child_hypothesis_id=outcome.hypothesis_id,
                                child_attempt_id=outcome.attempt_id,
                            )
                        if (
                            incomplete is None
                            or outcome.status is StageStatus.FAILED
                            and incomplete.status is StageStatus.BLOCKED
                        ):
                            incomplete = outcome
                        continue
                    self._register_chain_children(run, child, static)
            if not made_progress:
                break

        candidate_after: str | None = None
        while True:
            candidates = self._store.list_candidates(
                identity,
                scope,
                status=("INCLUDE", "UNDECIDED"),
                after_id=candidate_after,
                limit=32,
            )
            if not candidates:
                break
            for candidate in candidates:
                candidate_after = candidate.candidate_id
                if candidate.deep_status == "NO_HYPOTHESIS":
                    continue
                linked_after: str | None = None
                terminal = True
                any_link = False
                while True:
                    links = self._store.list_candidate_hypothesis_ids(
                        identity,
                        scope,
                        candidate.candidate_id,
                        after_id=linked_after,
                        limit=32,
                    )
                    if not links:
                        break
                    any_link = True
                    linked_after = links[-1]
                    if any(
                        not self._candidate_hypothesis_terminal(identity, linked)
                        for linked in links
                    ):
                        terminal = False
                if any_link and terminal:
                    self._store.save_candidate_deep_status(
                        identity, scope, candidate.candidate_id, "COMPLETE"
                    )
        if incomplete is not None:
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="FAILED"
                if incomplete.status is StageStatus.FAILED
                else "BLOCKED",
                current_stage=incomplete.current_stage,
                error_code=incomplete.error_code,
                child_hypothesis_id=incomplete.hypothesis_id,
                child_attempt_id=incomplete.attempt_id,
            )
        counts = self._store.candidate_counts(identity, scope)
        deep = self._store.candidate_deep_counts(identity, scope)
        if (
            counts.get("PENDING", 0)
            or counts.get("ERROR", 0)
            or self._store.list_incomplete_hypotheses(identity, limit=1)
            or any(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
        ):
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=latest_stage,
                error_code="CANDIDATE_WORK_INCOMPLETE",
            )
        terminal_status: Literal["COMPLETE", "PARTIAL"] = (
            "PARTIAL" if run.static_disposition == "PARTIAL" else "COMPLETE"
        )
        self._store.save_analysis_run(
            run.model_copy(
                update={
                    "candidate_terminal": CandidateTerminal(
                        status=terminal_status,
                        bundle_hash=static.static_bundle_ref.content_hash,
                        scope_fingerprint=scope,
                        decision_counts=counts,
                        deep_counts=deep,
                        hypothesis_count=self._store.hypothesis_count(identity),
                    )
                }
            )
        )
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status=terminal_status,
            current_stage=latest_stage,
        )

    def _candidate_bootstrap_failure(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        code: str,
        *,
        paused: bool = False,
        evidence_refs: tuple[StoredDataRef, ...] = (),
        current_checkpoint: StageCheckpoint | None = None,
    ) -> SimpleAnalysisOutcome:
        existing = self._store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
            and existing is not None
            and existing.status in {StageStatus.BLOCKED, StageStatus.FAILED}
        ):
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status="BLOCKED",
                current_stage=existing.stage,
                error_code=code,
            )
        checkpoint = (
            current_checkpoint
            if current_checkpoint is not None
            and current_checkpoint.status is StageStatus.RUNNING
            and current_checkpoint.input_refs
            and current_checkpoint.input_refs[0] == static.static_bundle_ref
            else self._store.mark_running(
                identity,
                SimpleStage.HYPOTHESIS_DONE,
                (static.static_bundle_ref,),
                attempt_id=uuid4().hex,
            )
        )
        self._store.mark_failure(
            checkpoint,
            StageFailure(
                code=code,
                retryable=False,
                safe_message="Candidate analysis did not complete",
                evidence_refs=evidence_refs,
            ),
            StageStatus.BLOCKED,
        )
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status="PAUSED" if paused else "BLOCKED",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
            error_code=code,
        )

    async def _propose_and_run(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        *,
        append_existing: bool = False,
    ) -> SimpleAnalysisOutcome:
        existing_refs = (
            self._known_proposal_refs(run, identity) if append_existing else ()
        )
        existing_keys = {
            self._proposal_key(identity, ref, strict=True) for ref in existing_refs
        }
        while True:
            should_retry, terminal = await self._resume_bootstrap_failure(
                identity,
                SimpleStage.HYPOTHESIS_DONE,
            )
            if should_retry:
                continue
            if terminal is not None:
                return self._bootstrap_outcome(run, terminal)
            input_refs = (
                (static.static_bundle_ref,)
                if append_existing
                else tuple(
                    dict.fromkeys(
                        (static.static_bundle_ref,)
                        + self._store.input_refs_for(
                            identity, SimpleStage.HYPOTHESIS_DONE
                        )
                    )
                )
            )
            checkpoint = self._store.mark_running(
                identity,
                SimpleStage.HYPOTHESIS_DONE,
                input_refs,
                attempt_id=uuid4().hex,
            )
            try:
                proposed = await self._hypotheses.propose(identity, static)
                if isinstance(proposed, StageFailure):
                    failure = proposed
                elif not proposed:
                    raise ValueError("HYPOTHESIS_OUTPUT_EMPTY")
                else:
                    seeds_list: list[HypothesisSeed] = []
                    seen_ids = set(run.hypothesis_ids)
                    seen_keys = set(existing_keys)
                    for seed in proposed:
                        proposal_key = self._proposal_key(
                            identity, seed.proposal_ref, strict=append_existing
                        )
                        if seed.hypothesis_id in seen_ids or proposal_key in seen_keys:
                            continue
                        seen_ids.add(seed.hypothesis_id)
                        seen_keys.add(proposal_key)
                        seeds_list.append(seed)
                    seeds = tuple(seeds_list)
                    self._store.complete(
                        checkpoint,
                        self._stage_result(
                            *existing_refs, *(seed.proposal_ref for seed in seeds)
                        ),
                    )
                    break
            except Exception as error:
                failure = StageFailure(
                    code=self._safe_error_code(
                        error,
                        "HYPOTHESIS_BOOTSTRAP_BLOCKED",
                    ),
                    retryable=not isinstance(error, StaticEvidenceInvalid),
                    safe_message="Hypothesis generation did not complete",
                )
            failed = self._store.mark_failure(
                checkpoint,
                failure,
                StageStatus.BLOCKED if failure.retryable else StageStatus.FAILED,
            )
            if await self._prepare_bootstrap_retry(failed, failure):
                continue
            return self._bootstrap_outcome(
                run,
                self._store.require(identity, SimpleStage.HYPOTHESIS_DONE),
            )
        for seed in seeds:
            child = identity.model_copy(update={"hypothesis_id": seed.hypothesis_id})
            inputs = (seed.proposal_ref, static.static_bundle_ref)
            self._store.save_checkpoint(
                StageCheckpoint(
                    identity=child,
                    stage=SimpleStage.PRO_CON_DONE,
                    status=StageStatus.PENDING,
                    input_refs=inputs,
                    input_hash=input_reference_hash(inputs),
                )
            )
        run = run.model_copy(
            update={
                "hypothesis_ids": run.hypothesis_ids
                + tuple(seed.hypothesis_id for seed in seeds)
            }
        )
        self._store.save_analysis_run(run)
        return await self._run_hypotheses(run, identity, static)

    def _known_proposal_refs(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> tuple[StoredDataRef, ...]:
        refs: list[StoredDataRef] = []
        for hypothesis_id in run.hypothesis_ids:
            child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
            checkpoint = self._store.get(child, SimpleStage.PRO_CON_DONE)
            if checkpoint is None or len(checkpoint.input_refs) < 2:
                raise StaticEvidenceInvalid()
            refs.append(checkpoint.input_refs[0])
        return tuple(refs)

    def _proposal_key(
        self,
        identity: CheckpointIdentity,
        ref: StoredDataRef,
        *,
        strict: bool = False,
    ) -> str:
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            value = json.loads(artifacts.read_prompt_proposal(ref))
        except (OSError, ValueError) as error:
            if str(error) == "HYPOTHESIS_PROPOSAL_ORIGINAL_INVALID":
                raise StaticEvidenceInvalid() from error
            if strict:
                raise StaticEvidenceInvalid() from None
            return ref.content_hash  # Legacy test/bootstrap refs have no artifact.
        if not isinstance(value, dict) or not isinstance(value.get("proposal"), dict):
            raise StaticEvidenceInvalid()
        return hashlib.sha256(canonical_bytes(value["proposal"])).hexdigest()

    async def _resume_bootstrap_failure(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
    ) -> tuple[bool, StageCheckpoint | None]:
        existing = self._store.get(identity, stage)
        if (
            stage is SimpleStage.STATIC_DONE
            and existing is not None
            and existing.status is StageStatus.BLOCKED
            and not existing.retryable
        ):
            fingerprint_method = getattr(self._static, "coverage_fingerprint", None)
            if fingerprint_method is None:
                return False, existing
            saved_fingerprint: str | None = None
            artifacts = SimpleArtifactRepository(self._data_dir, identity)
            for ref in existing.output_refs:
                try:
                    value = json.loads(artifacts.read(ref))
                except (OSError, ValueError):
                    continue
                if (
                    isinstance(value, dict)
                    and value.get("kind") == "simple_static_coverage_v1"
                ):
                    raw_fingerprint = value.get("fingerprint")
                    if isinstance(raw_fingerprint, str):
                        saved_fingerprint = raw_fingerprint
                    break
            if saved_fingerprint is None:
                return False, existing
            run = self._store.require_analysis_run(identity.analysis_id)
            try:
                current = await fingerprint_method(
                    SimpleAnalysisRequest(
                        data_dir=self._data_dir,
                        repository=run.repository,
                        commit=run.commit_id,
                    ),
                    identity,
                )
            except (OSError, RuntimeError, ValueError):
                return False, existing
            if current == saved_fingerprint:
                return False, existing
            return False, None
        if (
            existing is not None
            and existing.status in {StageStatus.BLOCKED, StageStatus.FAILED}
            and not existing.retryable
        ):
            return False, existing
        if self._recovery_factory is None:
            return False, None
        if existing is None or existing.status in {
            StageStatus.PENDING,
            StageStatus.SUCCEEDED,
        }:
            return False, None
        if existing.status is StageStatus.RUNNING:
            failure = StageFailure(
                code="STAGE_INTERRUPTED",
                retryable=True,
                safe_message="Bootstrap execution was interrupted",
            )
            failed = self._store.mark_failure(
                existing,
                failure,
                StageStatus.BLOCKED,
            )
            if stage is SimpleStage.STATIC_DONE:
                # The exclusive run lease proves the interrupted scanner stopped.
                # Recheck durable scan evidence directly instead of spending LLM.
                return False, None
        else:
            if not existing.retryable:
                return False, existing
            failure = StageFailure(
                code=existing.error_code or "BOOTSTRAP_RECOVERY_REQUIRED",
                retryable=True,
                safe_message="Resume the recorded bootstrap failure",
                evidence_refs=existing.output_refs,
            )
            failed = existing
        if await self._prepare_bootstrap_retry(failed, failure):
            return True, None
        return False, self._store.require(identity, stage)

    async def _prepare_bootstrap_retry(
        self,
        failed: StageCheckpoint,
        failure: StageFailure,
    ) -> bool:
        if self._recovery_factory is None or not failure.retryable:
            return False
        if failed.attempt_number >= MAX_RECOVERY_ATTEMPTS:
            self._store.mark_recovery_exhausted(failed)
            return False
        resolution = await self._recovery_factory(failed.identity).decide(
            failed,
            failure,
        )
        if resolution.decision.action in {
            RecoveryAction.RETRY_STAGE,
            RecoveryAction.REGENERATE_INPUT,
        }:
            self._store.prepare_recovery(failed, resolution, failed.stage)
            return True
        if resolution.decision.action is RecoveryAction.STOP:
            self._store.record_recovery_stop(failed, resolution)
        else:
            self._store.record_recovery_decision(failed, resolution)
        return False

    @staticmethod
    def _bootstrap_outcome(
        run: SimpleAnalysisRun,
        failed: StageCheckpoint,
    ) -> SimpleAnalysisOutcome:
        status: Literal["BLOCKED", "FAILED"] = (
            "FAILED" if failed.status is StageStatus.FAILED else "BLOCKED"
        )
        return SimpleAnalysisOutcome(
            identity=failed.identity,
            display_analysis_id=run.display_analysis_id,
            status=status,
            current_stage=failed.stage,
            error_code=failed.error_code,
            child_hypothesis_id=failed.identity.hypothesis_id,
            child_attempt_id=failed.attempt_id,
        )

    async def _run_hypotheses(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
        self._invalidate_stale_report_coverage(run, identity)
        latest_stage = SimpleStage.HYPOTHESIS_DONE
        incomplete: RunOutcome | None = None
        index = 0
        while index < len(run.hypothesis_ids):
            batch_ids = run.hypothesis_ids[
                index : index + self._max_parallel_hypotheses
            ]
            children = tuple(
                identity.model_copy(update={"hypothesis_id": hypothesis_id})
                for hypothesis_id in batch_ids
            )
            outcomes = await asyncio.gather(
                *(
                    self._runner_factory(
                        self._store,
                        child,
                        self._static_for_child(static, child),
                    ).resume_hypothesis(child)
                    for child in children
                )
            )
            index += len(children)
            for child, outcome in zip(children, outcomes, strict=True):
                outcome = outcome.model_copy(
                    update={"hypothesis_id": child.hypothesis_id}
                )
                latest_stage = outcome.current_stage
                if outcome.status in {StageStatus.BLOCKED, StageStatus.FAILED}:
                    if (
                        incomplete is None
                        or outcome.status is StageStatus.FAILED
                        and incomplete.status is StageStatus.BLOCKED
                    ):
                        incomplete = outcome
                    continue
                try:
                    run = self._register_chain_children(run, child, static)
                except ChainingEvidenceInvalid as error:
                    failed = self._block_invalid_chaining(error.checkpoint)
                    if incomplete is None:
                        incomplete = RunOutcome(
                            current_stage=failed.stage,
                            status=failed.status,
                            error_code=failed.error_code,
                            hypothesis_id=failed.identity.hypothesis_id,
                            attempt_id=failed.attempt_id,
                        )
        if incomplete is not None:
            outcome_status: Literal["BLOCKED", "FAILED"] = (
                "BLOCKED" if incomplete.status is StageStatus.BLOCKED else "FAILED"
            )
            return SimpleAnalysisOutcome(
                identity=identity,
                display_analysis_id=run.display_analysis_id,
                status=outcome_status,
                current_stage=incomplete.current_stage,
                error_code=incomplete.error_code,
                child_hypothesis_id=incomplete.hypothesis_id,
                child_attempt_id=incomplete.attempt_id,
            )
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL" if run.static_disposition == "PARTIAL" else "COMPLETE",
            current_stage=latest_stage,
        )

    def _durable_hypothesis_ids(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> Iterator[str]:
        if run.candidate_pipeline_version not in {1, 2}:
            yield from run.hypothesis_ids
            return
        after_id: str | None = None
        while True:
            ids = self._store.list_hypotheses(identity, after_id=after_id, limit=64)
            if not ids:
                return
            yield from ids
            after_id = ids[-1]

    def _invalidate_stale_report_coverage(
        self, run: SimpleAnalysisRun, identity: CheckpointIdentity
    ) -> None:
        """A completed Finding can keep its agents while its report is refreshed."""

        for hypothesis_id in self._durable_hypothesis_ids(run, identity):
            child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
            report = self._store.get(child, SimpleStage.REPORT_DONE)
            if (
                report is None
                or report.status is not StageStatus.SUCCEEDED
                or report.bundle_manifest_ref is None
            ):
                continue
            finding = self._store.get(child, SimpleStage.FINDING_DONE)
            if finding is None or not finding.output_refs:
                continue
            artifacts = SimpleArtifactRepository(self._data_dir, child)
            recorded_ref, recorded_disposition = artifacts.published_report_coverage(
                report, finding.output_refs[0]
            )
            if (
                recorded_ref != run.static_coverage_ref
                or recorded_disposition is not None
                and recorded_disposition != run.static_disposition
            ):
                self._store.invalidate_from(
                    child,
                    SimpleStage.REPORT_DONE,
                    new_inputs=report.input_refs,
                    force=True,
                )

    def _static_for_child(
        self, static: StaticBootstrapResult, child: CheckpointIdentity
    ) -> StaticBootstrapResult:
        checkpoint = self._store.get(child, SimpleStage.PRO_CON_DONE)
        if checkpoint is None or len(checkpoint.input_refs) < 2:
            return static
        return static.model_copy(update={"static_bundle_ref": checkpoint.input_refs[1]})

    def _register_chain_children(
        self,
        run: SimpleAnalysisRun,
        parent: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisRun:
        checkpoint = self._store.get(parent, SimpleStage.CHAINING_DONE)
        if checkpoint is None or checkpoint.status is not StageStatus.SUCCEEDED:
            return run
        if len(checkpoint.output_refs) != 1:
            raise ChainingEvidenceInvalid(checkpoint)
        return self._register_chaining_result(
            run, parent, static, checkpoint, checkpoint.output_refs[0]
        )

    def _register_chaining_result(
        self,
        run: SimpleAnalysisRun,
        parent: CheckpointIdentity,
        static: StaticBootstrapResult,
        checkpoint: StageCheckpoint,
        result_ref: StoredDataRef,
    ) -> SimpleAnalysisRun:
        artifacts = SimpleArtifactRepository(self._data_dir, parent)
        try:
            value = json.loads(artifacts.read(result_ref))
        except (OSError, ValueError, TypeError, sqlite3.Error) as error:
            raise ChainingEvidenceInvalid(checkpoint) from error
        if not isinstance(value, dict):
            raise ChainingEvidenceInvalid(checkpoint)
        children = value.get("children")
        if (
            value.get("kind") != "simple_chaining_result"
            or value.get("analysis_id") != parent.analysis_id
            or value.get("source_hypothesis_id") != parent.hypothesis_id
            or not isinstance(value.get("considered_primitive_refs"), list)
            or not isinstance(children, list)
            or len(children) > 4
            or value.get("status")
            != ("MATERIAL_CHILD" if children else "NO_MATERIAL_CHILD")
            or any(
                not isinstance(child, dict)
                or any(
                    not isinstance(child.get(key), str)
                    for key in (
                        "upstream_primitive_hash",
                        "downstream_primitive_hash",
                        "title",
                        "vulnerability_type",
                        "summary",
                        "rationale",
                    )
                )
                or not isinstance(child.get("code_locations"), list)
                or not all(
                    isinstance(location, str) for location in child["code_locations"]
                )
                or not isinstance(child.get("parent_hypothesis_ids"), list)
                or not child["parent_hypothesis_ids"]
                or not all(
                    isinstance(hypothesis_id, str)
                    for hypothesis_id in child["parent_hypothesis_ids"]
                )
                or not isinstance(child.get("parent_primitive_refs"), list)
                for child in children
            )
        ):
            raise ChainingEvidenceInvalid(checkpoint)
        if children:
            try:
                considered = tuple(
                    StoredDataRef.model_validate(item)
                    for item in value["considered_primitive_refs"]
                )
                admitted = {
                    ref: item
                    for item in self._store.list_checkpoints(run.analysis_id)
                    if item.stage is SimpleStage.PRIMITIVE_ADMISSION_DONE
                    and item.stage_version == STAGE_VERSION[item.stage]
                    and item.status is StageStatus.SUCCEEDED
                    and item.identity.analysis_id == parent.analysis_id
                    and item.identity.workspace_id == parent.workspace_id
                    and item.identity.commit_id == parent.commit_id
                    and item.identity.hypothesis_id is not None
                    and (
                        self._store.has_hypothesis(
                            parent.model_copy(update={"hypothesis_id": None}),
                            item.identity.hypothesis_id,
                        )
                        if run.candidate_pipeline_version in {1, 2}
                        else item.identity.hypothesis_id in run.hypothesis_ids
                    )
                    for ref in item.output_refs
                }
                primitives: dict[str, tuple[StoredDataRef, str]] = {}
                for ref in considered:
                    owner = admitted.get(ref)
                    if owner is None or ref.content_hash in primitives:
                        raise ChainingEvidenceInvalid(checkpoint)
                    primitive = json.loads(artifacts.read(ref))
                    if (
                        not isinstance(primitive, dict)
                        or primitive.get("kind") != "simple_primitive"
                        or primitive.get("analysis_id") != parent.analysis_id
                        or primitive.get("workspace_id") != parent.workspace_id
                        or primitive.get("commit_id") != parent.commit_id
                        or owner.identity.hypothesis_id is None
                        or primitive.get("source_hypothesis_id")
                        != owner.identity.hypothesis_id
                    ):
                        raise ChainingEvidenceInvalid(checkpoint)
                    primitives[ref.content_hash] = (
                        ref,
                        owner.identity.hypothesis_id,
                    )
                for child_value in children:
                    upstream = primitives.get(child_value["upstream_primitive_hash"])
                    downstream = primitives.get(
                        child_value["downstream_primitive_hash"]
                    )
                    if upstream is None or downstream is None or upstream == downstream:
                        raise ChainingEvidenceInvalid(checkpoint)
                    parent_refs = tuple(
                        StoredDataRef.model_validate(item)
                        for item in child_value["parent_primitive_refs"]
                    )
                    expected_parents = sorted({upstream[1], downstream[1]})
                    if (
                        parent_refs != (upstream[0], downstream[0])
                        or child_value["parent_hypothesis_ids"] != expected_parents
                    ):
                        raise ChainingEvidenceInvalid(checkpoint)
            except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
                raise ChainingEvidenceInvalid(checkpoint) from error
        hypothesis_ids = list(run.hypothesis_ids)
        parents = dict(run.parent_hypothesis_ids)
        depths = dict(run.chain_depths)
        changed = False
        for child_value in children:
            if not isinstance(child_value, dict) or (
                run.candidate_pipeline_version not in {1, 2}
                and len(hypothesis_ids) >= 32
            ):
                continue
            parent_ids = tuple(
                str(item) for item in child_value.get("parent_hypothesis_ids", [])
            )
            root_identity = parent.model_copy(update={"hypothesis_id": None})
            if run.candidate_pipeline_version in {1, 2}:
                parent_depths = []
                for item in parent_ids:
                    metadata = self._store.hypothesis_metadata(root_identity, item)
                    if metadata is None:
                        raise ChainingEvidenceInvalid(checkpoint)
                    parent_depths.append(metadata[0])
            else:
                parent_depths = [depths.get(item, 0) for item in parent_ids]
            depth = 1 + max(parent_depths, default=0)
            if not parent_ids or depth > 4:
                continue
            hypothesis_id = (
                "hypothesis-chain-"
                + hashlib.sha256(canonical_bytes(child_value)).hexdigest()[:32]
            )
            if (
                self._store.has_hypothesis(root_identity, hypothesis_id)
                if run.candidate_pipeline_version in {1, 2}
                else hypothesis_id in hypothesis_ids
            ):
                continue
            proposal_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "origin": "CHAINING",
                    "analysis_id": parent.analysis_id,
                    "hypothesis_id": hypothesis_id,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "parent_chaining_result_ref": result_ref.model_dump(mode="json"),
                    "proposal": child_value,
                }
            )
            child_identity = parent.model_copy(update={"hypothesis_id": hypothesis_id})
            inputs = (proposal_ref, static.static_bundle_ref)
            pending = StageCheckpoint(
                identity=child_identity,
                stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
            )
            if run.candidate_pipeline_version in {1, 2}:
                self._store.register_free_hypothesis(
                    root_identity,
                    hypothesis_id,
                    proposal_ref,
                    pending,
                    chain_depth=depth,
                    parent_hypothesis_ids=parent_ids,
                )
            else:
                self._store.save_checkpoint(pending)
                hypothesis_ids.append(hypothesis_id)
                parents[hypothesis_id] = parent_ids
                depths[hypothesis_id] = depth
            changed = True
        if not changed or run.candidate_pipeline_version in {1, 2}:
            return run
        updated = run.model_copy(
            update={
                "hypothesis_ids": tuple(hypothesis_ids),
                "parent_hypothesis_ids": parents,
                "chain_depths": depths,
            }
        )
        self._store.save_analysis_run(updated)
        return updated

    def _block_invalid_chaining(self, checkpoint: StageCheckpoint) -> StageCheckpoint:
        return self._store.mark_failure(
            checkpoint,
            StageFailure(
                code="CHAINING_EVIDENCE_INVALID",
                retryable=False,
                safe_message="Stored chaining evidence cannot be trusted",
                evidence_refs=checkpoint.output_refs,
            ),
            StageStatus.BLOCKED,
        )

    @staticmethod
    def _stage_result(*refs: StoredDataRef) -> StageResult:
        return StageResult(output_refs=tuple(refs))

    @staticmethod
    def _safe_error_code(error: Exception, fallback: str) -> str:
        message = str(error)
        if message and all(
            character.isupper() or character.isdigit() or character in "_:"
            for character in message
        ):
            return message[:160]
        return fallback


__all__ = [
    "HypothesisSeed",
    "SimpleAnalysisApplication",
    "SimpleAnalysisOutcome",
    "SimpleAnalysisRequest",
    "SimpleAnalysisRun",
    "StaticBootstrapResult",
]
