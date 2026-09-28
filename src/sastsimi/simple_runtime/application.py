"""Application service for new and resumed local repository analyses."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore

from .artifacts import SimpleArtifactRepository
from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from .recovery import (
    MAX_RECOVERY_ATTEMPTS,
    RecoveryAction,
    RecoveryCoordinator,
)
from .run_lease import AnalysisRunBusy, analysis_run_lease
from .runner import RunOutcome, SimpleRuntimeRunner
from .store import SimpleCheckpointStore


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


class HypothesisSeed(ContractModel):
    hypothesis_id: str
    proposal_ref: StoredDataRef


class SimpleAnalysisOutcome(ContractModel):
    identity: CheckpointIdentity
    display_analysis_id: str
    status: Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE", "PARTIAL"]
    current_stage: SimpleStage
    error_code: str | None = None


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
    ) -> None:
        if not 1 <= max_parallel_hypotheses <= 32:
            raise ValueError("PARALLEL_HYPOTHESIS_LIMIT_INVALID")
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
        self._max_parallel_hypotheses = max_parallel_hypotheses
        self._max_elapsed_seconds = max_elapsed_seconds
        self._max_tokens = max_tokens

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

    async def resume(self, analysis_id_or_display: str) -> SimpleAnalysisOutcome:
        exact = self._display.resolve(analysis_id_or_display)
        try:
            with analysis_run_lease(self._data_dir, exact):
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

    async def _resume_locked(self, exact: str) -> SimpleAnalysisOutcome:
        run = self._store.require_analysis_run(exact)
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
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
        if run.static_coverage_ref is not None:
            try:
                run = self._reconcile_hypothesis_checkpoint(run, identity)
            except StaticEvidenceInvalid:
                return self._invalid_partial_resume(run, identity)
        self._promote_legacy_inconclusive_pocs(exact)
        if self._max_elapsed_seconds is not None:
            self._store.reopen_elapsed_budget_failures(exact, self._max_elapsed_seconds)
        if self._max_tokens == "unlimited":
            self._store.reopen_token_budget_failures(exact)
        if (
            run.workspace_path is None
            or run.repository_profile_ref is None
            or run.static_bundle_ref is None
            or run.static_disposition == "PARTIAL"
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
        failed = self._store.mark_failure(
            checkpoint,
            StageFailure(
                code="HYPOTHESIS_EVIDENCE_INVALID",
                retryable=False,
                safe_message="Stored hypothesis evidence cannot be trusted",
            ),
            StageStatus.BLOCKED,
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
                payload = json.loads(artifacts.read(ref))
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
            if (
                not isinstance(coverage.get("fingerprint"), str)
                or coverage.get("unavailable") is True
                or type(expected) is not int
                or type(verified) is not int
                or expected < 1
                or not 0 <= verified <= expected
                or not isinstance(gaps, list)
                or not isinstance(unsupported, list)
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
            has_limitations = bool(
                gaps
                or unsupported
                or coverage.get("unsupported_files")
                or coverage.get("codeql_error")
                or coverage.get("ast_parse_error_count")
                or coverage.get("ast_oversize_count")
            )
            if static.static_disposition == "PARTIAL":
                if verified == 0 or not has_limitations:
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
        """Reclassify only exact exhausted PoCs that actually ran inconclusively."""

        promoted = 0
        for checkpoint in self._store.list_checkpoints(analysis_id):
            if (
                checkpoint.stage is not SimpleStage.POC_EXECUTION_DONE
                or checkpoint.stage_version
                != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
                or checkpoint.status is not StageStatus.BLOCKED
                or checkpoint.error_code != "RECOVERY_EXHAUSTED"
                or checkpoint.attempt_number < MAX_RECOVERY_ATTEMPTS
                or len(checkpoint.output_refs) != 2
                or checkpoint.validated_poc_ref is not None
            ):
                continue
            execution_ref, interpretation_ref = checkpoint.output_refs
            artifacts = SimpleArtifactRepository(self._data_dir, checkpoint.identity)
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
                        if (
                            seed.hypothesis_id in seen_ids
                            or proposal_key in seen_keys
                        ):
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
            value = json.loads(artifacts.read(ref))
        except (OSError, ValueError):
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
        )

    async def _run_hypotheses(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleAnalysisOutcome:
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
                latest_stage = outcome.current_stage
                if outcome.status in {StageStatus.BLOCKED, StageStatus.FAILED}:
                    if (
                        incomplete is None
                        or outcome.status is StageStatus.FAILED
                        and incomplete.status is StageStatus.BLOCKED
                    ):
                        incomplete = outcome
                    continue
                run = self._register_chain_children(run, child, static)
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
            )
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL" if run.static_disposition == "PARTIAL" else "COMPLETE",
            current_stage=latest_stage,
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
        if checkpoint is None or len(checkpoint.output_refs) != 1:
            return run
        artifacts = SimpleArtifactRepository(self._data_dir, parent)
        try:
            value = json.loads(artifacts.read(checkpoint.output_refs[0]))
            children = value.get("children", [])
        except (OSError, ValueError, json.JSONDecodeError):
            return run
        if not isinstance(children, list):
            return run
        hypothesis_ids = list(run.hypothesis_ids)
        parents = dict(run.parent_hypothesis_ids)
        depths = dict(run.chain_depths)
        changed = False
        for child_value in children:
            if not isinstance(child_value, dict) or len(hypothesis_ids) >= 32:
                continue
            parent_ids = tuple(
                str(item) for item in child_value.get("parent_hypothesis_ids", [])
            )
            depth = 1 + max((depths.get(item, 0) for item in parent_ids), default=0)
            if not parent_ids or depth > 4:
                continue
            hypothesis_id = (
                "hypothesis-chain-"
                + hashlib.sha256(canonical_bytes(child_value)).hexdigest()[:32]
            )
            if hypothesis_id in hypothesis_ids:
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
                    "parent_chaining_result_ref": checkpoint.output_refs[0].model_dump(
                        mode="json"
                    ),
                    "proposal": child_value,
                }
            )
            child_identity = parent.model_copy(update={"hypothesis_id": hypothesis_id})
            inputs = (proposal_ref, static.static_bundle_ref)
            self._store.save_checkpoint(
                StageCheckpoint(
                    identity=child_identity,
                    stage=SimpleStage.PRO_CON_DONE,
                    status=StageStatus.PENDING,
                    input_refs=inputs,
                    input_hash=input_reference_hash(inputs),
                )
            )
            hypothesis_ids.append(hypothesis_id)
            parents[hypothesis_id] = parent_ids
            depths[hypothesis_id] = depth
            changed = True
        if not changed:
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
