"""Composition root for the public single-process SimpleRuntime."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import cast

from sastsimi.composition.local_codex_binding import build_local_codex_binding
from sastsimi.config.local_evaluation_profile import LocalCodexSubscriptionSettings
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    UserConfig,
    UserConfigStore,
    load_simple_execution_profile,
)
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.contracts.prompt_redaction import redact_local_file_urls
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.policy.adapters.official_http import (
    PinnedHttpsTransport,
    resolve_public_addresses,
)
from sastsimi.ports.public_commands import PublicCommandApplication
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.progress.projector import (
    ProgressProjector,
    verified_surface_coverage_counts,
)
from sastsimi.providers.codex_subscription import CodexCliProcessRunner
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.runtime.system_support import SystemClock, UUIDIds
from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.setup.service import SystemToolDiscovery
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import surface_index_from_json
from sastsimi.simple_runtime.bootstrap_stages import (
    DirectHypothesisBootstrap,
    DirectStaticBootstrap,
)
from sastsimi.simple_runtime.call_queue import RunLimitedClient, RunUsageBudget
from sastsimi.simple_runtime.claude_provider import (
    ClaudeProvider,
    OfficialClaudeCLITransport,
)
from sastsimi.simple_runtime.cursor_provider import (
    CursorCLIAuthenticationError,
    CursorModelCatalog,
    CursorProvider,
    OfficialCursorCLITransport,
    OfficialCursorTransport,
)
from sastsimi.simple_runtime.finding_group_projection import (
    project_current_finding_groups,
)
from sastsimi.simple_runtime.finding_groups import finding_group_rows
from sastsimi.simple_runtime.gate_guard import technical_gate_accepted
from sastsimi.simple_runtime.github_policy import GitHubPolicyDiscovery
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.poc_currentness import (
    stale_poc_hypothesis_ids,
    stale_successful_poc,
)
from sastsimi.simple_runtime.portable_docker import (
    DirectEnvironmentPreparer,
    PortableContainerFactory,
    PortableDockerRuntime,
)
from sastsimi.simple_runtime.provider import (
    SimpleCodexClient,
    SimpleLLMClient,
    SimpleOpenAIClient,
)
from sastsimi.simple_runtime.recovery import SimpleRecoveryCoordinator
from sastsimi.simple_runtime.report_currentness import (
    candidate_report_currentness_blocked,
)
from sastsimi.simple_runtime.run_lease import analysis_run_lease_active
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.scope_policy import (
    project_scope_review,
    safe_public_report,
)
from sastsimi.simple_runtime.stages import build_stage_handlers
from sastsimi.simple_runtime.store import SimpleCheckpointStore

from .simple_process import LocalProcessExecutor

_MAX_SURFACE_PROGRESS_BYTES = 64 * 1024 * 1024


def _codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


async def list_cursor_models() -> set[str]:
    """Account-specific Cursor model IDs without exposing the credential."""
    import tempfile

    key = os.environ.get("CURSOR_API_KEY", "")
    inspection = SystemToolDiscovery._inspect_cursor_agent()
    if inspection.available and inspection.executable is not None:
        client = OfficialCursorCLITransport(str(inspection.executable))
        try:
            return await client.list_models("")
        except CursorCLIAuthenticationError:
            if not key:
                raise
    if key and key == key.strip():
        return await OfficialCursorTransport(tempfile.gettempdir()).list_models(key)
    raise ValueError("CURSOR_CLI_NOT_INSTALLED")


class SimpleClientFactory:
    def __init__(self, profile: SimpleExecutionProfile) -> None:
        self._profile = profile
        self._semaphore = asyncio.Semaphore(profile.llm_max_concurrency)
        self._cursor_models = CursorModelCatalog()
        self._store = SimpleCheckpointStore(
            profile.data_dir / "db" / "sastsimi.sqlite3",
            artifact_data_dir=profile.data_dir,
        )

    def _budget(self, identity: CheckpointIdentity) -> RunUsageBudget:
        return RunUsageBudget(
            store=self._store,
            analysis_id=identity.analysis_id,
            max_tokens=self._profile.max_tokens,
            max_cost_minor_units=self._profile.max_cost_minor_units,
            max_elapsed_seconds=self._profile.max_elapsed_seconds,
        )

    def _limited(
        self,
        inner: SimpleLLMClient,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
        model: str,
        *,
        max_retries: int | None = None,
    ) -> RunLimitedClient:
        return RunLimitedClient(
            inner=inner,
            semaphore=self._semaphore,
            artifacts=artifacts,
            store=self._store,
            model=model,
            max_retries=self._profile.llm_max_retries
            if max_retries is None
            else max_retries,
            max_tokens=self._profile.max_tokens,
            max_cost_minor_units=self._profile.max_cost_minor_units,
            max_elapsed_seconds=self._profile.max_elapsed_seconds,
        )

    def __call__(
        self,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
    ) -> SimpleLLMClient:
        if self._profile.provider == "claude":
            try:
                tool = self._profile.tools["claude"]
            except KeyError:
                raise ValueError("CLAUDE_CLI_NOT_CONFIGURED") from None
            config_dir = Path(
                os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude"
            )
            return ClaudeProvider(
                artifacts=artifacts,
                default_model=self._profile.model,
                agent_models=self._profile.agent_models,
                timeout_seconds=self._profile.llm_timeout_seconds,
                max_retries=min(self._profile.llm_max_retries, 2),
                semaphore=self._semaphore,
                transport=OfficialClaudeCLITransport(tool, config_dir),
                budget_check=self._budget(identity).check,
            )
        if self._profile.provider == "cursor":
            fallback: SimpleLLMClient | None = None
            if self._profile.fallback_provider == "openai":
                fallback = self._limited(
                    SimpleOpenAIClient(
                        credential_ref="env:OPENAI_API_KEY",
                        model=self._profile.fallback_model or "",
                        artifacts=artifacts,
                    ),
                    identity,
                    artifacts,
                    self._profile.fallback_model or "",
                    max_retries=0,
                )
            elif self._profile.fallback_provider == "codex":
                fallback = self._limited(
                    self._codex(
                        identity, artifacts, self._profile.fallback_model or ""
                    ),
                    identity,
                    artifacts,
                    self._profile.fallback_model or "",
                    max_retries=0,
                )
            cli_login = self._profile.auth_mode == "SUBSCRIPTION_LOGIN"
            transport = None
            if cli_login:
                inspection = SystemToolDiscovery._inspect_cursor_agent()
                if not inspection.available or inspection.executable is None:
                    raise ValueError("CURSOR_CLI_NOT_INSTALLED")
                transport = OfficialCursorCLITransport(str(inspection.executable))
            return CursorProvider(
                artifacts=artifacts,
                default_model=self._profile.model,
                agent_models=self._profile.agent_models,
                timeout_seconds=self._profile.llm_timeout_seconds,
                max_retries=min(
                    self._profile.llm_max_retries,
                    1 if fallback is not None else 2,
                ),
                semaphore=self._semaphore,
                budget_check=self._budget(identity).check,
                allow_on_demand=self._profile.cursor_allow_on_demand,
                fallback=fallback,
                transport=transport,
                use_cli_login=cli_login,
                model_catalog=self._cursor_models,
            )
        if self._profile.provider == "openai":
            return self._limited(
                SimpleOpenAIClient(
                    credential_ref=self._profile.credential_ref,
                    model=self._profile.model,
                    artifacts=artifacts,
                ),
                identity,
                artifacts,
                self._profile.model,
            )
        return self._limited(
            self._codex(identity, artifacts, self._profile.model),
            identity,
            artifacts,
            self._profile.model,
        )

    def _codex(
        self,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
        model: str,
    ) -> SimpleCodexClient:
        try:
            tool = self._profile.tools["codex"]
        except KeyError:
            raise ValueError("CODEX_NOT_CONFIGURED") from None
        settings = LocalCodexSubscriptionSettings(
            provider_profile_key=self._profile.provider_profile_ref,
            executable_path=tool.executable_path,
            executable_sha256=tool.executable_sha256,
            codex_home=_codex_home(),
            client_version=tool.version,
            model=model,
        )
        scope = PlannedRunScope(
            analysis_id=AnalysisId(identity.analysis_id),
            workspace_id=WorkspaceId(identity.workspace_id),
            commit_id=CommitId(identity.commit_id),
            repository_ref="simple-runtime",
        )
        binding = build_local_codex_binding(
            settings=settings,
            scope=scope,
            artifacts=artifacts.artifacts,
            ids=UUIDIds(),
            clock=SystemClock(),
        )
        provider_ref = reference(binding.provider)
        if not isinstance(provider_ref, StoredDataRef):
            raise ValueError("SIMPLE_RUNTIME_PROVIDER_REFERENCE_INVALID")
        return SimpleCodexClient(
            runner=CodexCliProcessRunner(
                binding=binding.binding,
                on_child_spawning=lambda call_id, phase: (
                    self._store.begin_codex_child_spawn(
                        call_id=call_id,
                        analysis_id=identity.analysis_id,
                        phase=phase,
                    )
                ),
                on_child_started=lambda call_id, phase, pid, start: (
                    self._store.record_codex_child_spawn(
                        call_id=call_id,
                        analysis_id=identity.analysis_id,
                        phase=phase,
                        pid=pid,
                        start_identity=start,
                    )
                ),
                on_child_stopped=lambda call_id, phase, pid, start: (
                    self._store.mark_codex_child_exited(
                        call_id=call_id,
                        analysis_id=identity.analysis_id,
                        phase=phase,
                        pid=pid,
                        start_identity=start,
                    )
                ),
            ),
            provider_profile_ref=provider_ref,
            model=model,
            artifacts=artifacts,
        )


def build_analysis_application(
    config: UserConfig,
    profile: SimpleExecutionProfile,
) -> SimpleAnalysisApplication:
    data_dir = config.data_dir
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    client_factory = SimpleClientFactory(profile)
    docker = PortableDockerRuntime(profile)

    def recovery_factory(
        identity: CheckpointIdentity,
    ) -> SimpleRecoveryCoordinator:
        artifacts = SimpleArtifactRepository(data_dir, identity)
        return SimpleRecoveryCoordinator(
            client=client_factory(identity, artifacts),
            artifacts=artifacts,
        )

    def runner_factory(
        runtime_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        artifacts = SimpleArtifactRepository(data_dir, identity)
        client = client_factory(identity, artifacts)
        environments = DirectEnvironmentPreparer(
            docker=docker,
            artifacts=artifacts,
            workspace=static.workspace_path,
            wheel_bundle_path=profile.poc_wheel_archive_path,
            wheel_bundle_sha256=profile.poc_wheel_archive_sha256,
            git_executable=(
                str(profile.tools["git"].executable_path)
                if "git" in profile.tools
                else "git"
            ),
        )
        try:
            repository_url = runtime_store.require_analysis_run(
                identity.analysis_id
            ).repository
        except LookupError:
            repository_url = None
        return SimpleRuntimeRunner(
            runtime_store,
            build_stage_handlers(
                client=client,
                artifacts=artifacts,
                docker=cast(DockerAdapter, docker),
                containers=PortableContainerFactory(docker),
                environments=environments,
                store=runtime_store,
                security_policy_ref=static.security_policy_ref,
                policy_snapshot_ref=static.policy_snapshot_ref,
                repository_url=repository_url,
                workspace_path=static.workspace_path,
                static_bundle_ref=static.static_bundle_ref,
                git_executable=(
                    str(profile.tools["git"].executable_path)
                    if "git" in profile.tools
                    else "git"
                ),
            ),
            codex_invalid_output_resume=profile.provider == "codex",
            cleanup_artifacts=artifacts,
            recovery=recovery_factory(identity),
            policy_snapshot_ref=static.policy_snapshot_ref,
        )

    return SimpleAnalysisApplication(
        data_dir=data_dir,
        llm_provider=profile.provider,
        on_demand_possible=(
            profile.provider == "claude"
            or profile.provider == "cursor"
            and profile.cursor_allow_on_demand
        ),
        store=store,
        static_bootstrap=DirectStaticBootstrap(
            profile=profile,
            process=LocalProcessExecutor(),
            store=store,
            policy_discovery=GitHubPolicyDiscovery(
                transport=PinnedHttpsTransport(),
                resolver=resolve_public_addresses,
                clock=SystemClock(),
            ),
        ),
        hypothesis_bootstrap=DirectHypothesisBootstrap(
            data_dir=data_dir,
            client_factory=client_factory,
            feed=profile.hypothesis_feed,
            store=store,
            llm_timeout_seconds=profile.llm_timeout_seconds,
        ),
        runner_factory=runner_factory,
        profile_ref=profile.provider_profile_ref,
        provider=profile.provider,
        model=profile.model,
        recovery_factory=recovery_factory,
        max_parallel_hypotheses=profile.max_parallel_hypotheses,
        max_pending_candidate_children=profile.max_pending_candidate_children,
        max_elapsed_seconds=profile.max_elapsed_seconds,
        max_tokens=profile.max_tokens,
        max_cost_minor_units=profile.max_cost_minor_units,
        candidate_pipeline_enabled=True,
        candidate_client_factory=client_factory,
        candidate_hypothesis_bootstrap=DirectHypothesisBootstrap(
            data_dir=data_dir,
            client_factory=client_factory,
            feed="current",
            store=store,
            llm_timeout_seconds=profile.llm_timeout_seconds,
        ),
    )


class PublicSimpleRuntimeApplication(PublicCommandApplication):
    def __init__(self, config: UserConfig, profile: SimpleExecutionProfile) -> None:
        self._config = config
        self._profile = profile
        self._store = SimpleCheckpointStore(
            config.data_dir / "db" / "sastsimi.sqlite3",
            artifact_data_dir=config.data_dir,
        )
        self._display = AnalysisDisplayIdStore(self._store.database_path)

    def analyze(self, repository: str, commit: str) -> dict[str, object]:
        outcome = asyncio.run(
            build_analysis_application(self._config, self._profile).analyze(
                SimpleAnalysisRequest(
                    data_dir=self._config.data_dir,
                    repository=repository,
                    commit=commit,
                )
            )
        )
        return self._outcome(outcome.display_analysis_id, repository, commit)

    def analyze_with_progress(
        self,
        repository: str,
        commit: str,
        callback: Callable[[ProgressSnapshot], None],
    ) -> dict[str, object]:
        async def run() -> SimpleAnalysisOutcome:
            started: list[str] = []
            application = build_analysis_application(self._config, self._profile)
            task = asyncio.create_task(
                application.analyze(
                    SimpleAnalysisRequest(
                        data_dir=self._config.data_dir,
                        repository=repository,
                        commit=commit,
                    ),
                    on_analysis_started=started.append,
                )
            )
            outcome = await self._track(task, started, callback)
            return outcome

        outcome = asyncio.run(run())
        return self._outcome(outcome.display_analysis_id, repository, commit)

    def resume(self, analysis_id: str) -> dict[str, object]:
        outcome = asyncio.run(
            build_analysis_application(self._config, self._profile).resume(analysis_id)
        )
        run = self._store.require_analysis_run(outcome.identity.analysis_id)
        data = self._outcome(
            outcome.display_analysis_id,
            run.repository,
            run.commit_id,
        )
        if outcome.error_code == "ANALYSIS_ALREADY_RUNNING":
            data["resume_skipped_reason"] = outcome.error_code
        return data

    def resume_with_progress(
        self,
        analysis_id: str,
        callback: Callable[[ProgressSnapshot], None],
    ) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)

        async def run() -> SimpleAnalysisOutcome:
            task = asyncio.create_task(
                build_analysis_application(self._config, self._profile).resume(exact)
            )
            return await self._track(task, [exact], callback)

        outcome = asyncio.run(run())
        stored = self._store.require_analysis_run(outcome.identity.analysis_id)
        data = self._outcome(
            outcome.display_analysis_id,
            stored.repository,
            stored.commit_id,
        )
        if outcome.error_code == "ANALYSIS_ALREADY_RUNNING":
            data["resume_skipped_reason"] = outcome.error_code
        return data

    async def _track(
        self,
        task: asyncio.Task[SimpleAnalysisOutcome],
        started: list[str],
        callback: Callable[[ProgressSnapshot], None],
    ) -> SimpleAnalysisOutcome:
        last: ProgressSnapshot | None = None
        while not task.done():
            if started:
                try:
                    run = self._store.require_analysis_run(started[0])
                    current = self._progress_snapshot(run)
                except LookupError:
                    current = None
                if current is not None and current != last:
                    callback(current)
                    last = current
            await asyncio.sleep(0.2)
        outcome = await task
        if started:
            run = self._store.require_analysis_run(started[0])
            current = self._progress_snapshot(run)
            if current != last:
                callback(current)
        return outcome

    def _progress_snapshot(self, run: SimpleAnalysisRun) -> ProgressSnapshot:
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        scope = run.candidate_scope_fingerprint
        candidate_mode = run.candidate_pipeline_version in {1, 2}
        surface_counts, surface_index_hash = self._surface_metrics(run, identity, scope)
        return ProgressProjector(
            self._store, artifact_data_dir=self._config.data_dir
        ).snapshot(
            run.analysis_id,
            static_disposition=run.static_disposition,
            candidate_pipeline_version=run.candidate_pipeline_version or 0,
            candidate_counts=(
                self._store.candidate_counts(identity, scope)
                if candidate_mode and scope is not None
                else None
            ),
            candidate_deep_counts=(
                self._store.candidate_deep_counts(identity, scope)
                if candidate_mode and scope is not None
                else None
            ),
            registered_hypothesis_count=(
                self._store.hypothesis_count(identity) if candidate_mode else None
            ),
            candidate_terminal=run.candidate_terminal if candidate_mode else None,
            candidate_bundle_hash=(
                run.static_bundle_ref.content_hash
                if candidate_mode and run.static_bundle_ref is not None
                else None
            ),
            candidate_scope_fingerprint=scope if candidate_mode else None,
            surface_counts=surface_counts,
            surface_index_hash=surface_index_hash,
            analysis_active=(
                analysis_run_lease_active(self._config.data_dir, run.analysis_id)
                is True
            ),
        )

    def _surface_metrics(
        self,
        run: SimpleAnalysisRun,
        identity: CheckpointIdentity,
        scope: str | None,
    ) -> tuple[dict[str, int] | None, str | None]:
        if (
            run.candidate_pipeline_version != 2
            or scope is None
            or run.static_bundle_ref is None
        ):
            return None, None
        try:
            record = self._store.get_attack_surface_index(identity, scope)
            if record is None:
                return None, None
            repository = SimpleArtifactRepository(self._config.data_dir, identity)
            raw = repository.read_bounded(record.index_ref, _MAX_SURFACE_PROGRESS_BYTES)
            index = surface_index_from_json(json.loads(raw))
            if (
                record.static_bundle_hash != run.static_bundle_ref.content_hash
                or index.scope_fingerprint != scope
                or index.workspace_id != identity.workspace_id
                or index.commit_id != identity.commit_id
                or index.static_bundle_hash != record.static_bundle_hash
                or index.ast_manifest_hash != record.ast_manifest_hash
                or index.candidate_inventory_hash != record.candidate_inventory_hash
                or index.candidate_count != record.candidate_count
            ):
                return None, None
            progress = self._store.list_surface_exploration_progress(identity, scope)
        except (OSError, ValueError, sqlite3.Error):
            return None, None
        indexed = {surface.surface_id for surface in index.surfaces}
        matching_contexts = [
            item
            for item in progress.values()
            if item.surface_id in indexed
            and item.static_bundle_hash == record.static_bundle_hash
            and item.index_hash == record.index_ref.content_hash
        ]
        counts = {
            "TOTAL": len(indexed),
            "CONTEXT_RECORDS": len(matching_contexts),
            "CONTEXT_SURFACES": len({item.surface_id for item in matching_contexts}),
        }
        terminal = run.candidate_terminal
        if (
            terminal is not None
            and terminal.surface_index_hash == record.index_ref.content_hash
            and terminal.surface_coverage_hash
        ):
            try:
                coverage_ref = next(
                    (
                        ref
                        for checkpoint in self._store.list_checkpoints(run.analysis_id)
                        if checkpoint.identity == identity
                        and checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
                        and checkpoint.status is StageStatus.SUCCEEDED
                        for ref in checkpoint.output_refs
                        if ref.content_hash == terminal.surface_coverage_hash
                    ),
                    None,
                )
                verified = (
                    verified_surface_coverage_counts(
                        json.loads(
                            repository.read_bounded(
                                coverage_ref, _MAX_SURFACE_PROGRESS_BYTES
                            )
                        ),
                        index,
                        terminal,
                    )
                    if coverage_ref is not None
                    else None
                )
            except (OSError, ValueError, sqlite3.Error):
                verified = None
            if verified is not None:
                counts.update(verified)
        return counts, record.index_ref.content_hash

    def status(self, analysis_id: str) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)
        run = self._store.require_analysis_run(exact)
        snapshot = self._progress_snapshot(run)
        if candidate_report_currentness_blocked(
            run,
            self._store.list_checkpoints(exact),
            data_dir=self._config.data_dir,
            store=self._store,
        ):
            snapshot = snapshot.model_copy(update={"finding_count": 0})
        lease_inactive = (
            analysis_run_lease_active(self._config.data_dir, exact) is False
        )
        if run.candidate_pipeline_version in {1, 2} and lease_inactive:
            if self._store.unresolved_codex_call(exact) is not None:
                snapshot = snapshot.model_copy(
                    update={
                        "status": "BLOCKED",
                        "error_code": "CODEX_CALL_IN_FLIGHT_UNRESOLVED",
                    }
                )
            elif snapshot.status == "RUNNING":
                snapshot = snapshot.model_copy(
                    update={
                        "status": "PAUSED",
                        "error_code": "INTERRUPTED_RESUME_REQUIRED",
                        "resume_action": "RESUME_INTERRUPTED",
                    }
                )
        if snapshot.status in {"BLOCKED", "FAILED"} and snapshot.error_code in {
            "CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
        }:
            if (
                lease_inactive
                and self._confirmed_cleanup_resume_ready(exact)
                and analysis_run_lease_active(self._config.data_dir, exact) is False
            ):
                snapshot = snapshot.model_copy(
                    update={
                        "status": "PAUSED",
                        "error_code": "INTERRUPTED_RESUME_REQUIRED",
                        "resume_action": "RESUME_INTERRUPTED",
                    }
                )
            else:
                snapshot = snapshot.model_copy(
                    update={"resume_action": "MANUAL_CODEX_CLEANUP_REVIEW"}
                )
        return {
            "analysis_id": run.display_analysis_id,
            "exact_analysis_id": exact,
            "status": snapshot.status,
            "percent": snapshot.percent,
            "percentage_kind": snapshot.percentage_kind,
            "phase_counts": snapshot.phase_counts,
            "completed_units": snapshot.completed_units,
            "known_units": snapshot.known_units,
            "current_stage": snapshot.current_stage,
            "current_hypothesis_id": snapshot.current_hypothesis_id,
            "attempt_number": snapshot.attempt_number,
            "attempt_limit": snapshot.attempt_limit,
            "error_code": snapshot.error_code,
            "inconclusive_hypothesis_count": snapshot.inconclusive_hypothesis_count,
            "rejected_hypothesis_count": snapshot.rejected_hypothesis_count,
            "candidate_total_count": snapshot.candidate_total_count,
            "candidate_decision_counts": snapshot.candidate_decision_counts,
            "deep_analysis_running_count": snapshot.deep_analysis_running_count,
            "deep_analysis_completed_count": snapshot.deep_analysis_completed_count,
            "deep_analysis_pending_count": snapshot.deep_analysis_pending_count,
            "hypothesis_count": snapshot.hypothesis_count,
            "finding_count": snapshot.finding_count,
            "resume_action": snapshot.resume_action,
            **self._static_coverage_status(run),
        }

    def _confirmed_cleanup_resume_ready(self, analysis_id: str) -> bool:
        cleanup_errors = {
            "CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
        }
        try:
            checkpoints: tuple[StageCheckpoint, ...] = self._store.list_checkpoints(
                analysis_id
            )
            affected = [
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                and checkpoint.error_code in cleanup_errors
            ]
            if not affected or self._store.unresolved_codex_call(analysis_id):
                return False
            return all(
                self._store.has_codex_cleanup_confirmation(
                    checkpoint,
                    SimpleArtifactRepository(
                        self._config.data_dir, checkpoint.identity
                    ),
                )
                if checkpoint.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
                else self._store.confirmed_codex_call_covering(
                    analysis_id, checkpoint.updated_at
                )
                for checkpoint in affected
            )
        except (OSError, ValueError, LookupError, sqlite3.Error):
            return False

    def _static_coverage_status(self, run: SimpleAnalysisRun) -> dict[str, object]:
        """Expose only bounded, exact-verified static scope facts."""

        empty: dict[str, object] = {
            "static_coverage_status": "UNAVAILABLE",
            "static_coverage_digest": None,
            "static_coverage_expected": None,
            "static_coverage_verified": None,
        }
        categories = (
            ("gaps", "static_coverage_gap", ("path", "rule_id", "reason")),
            (
                "unavailable_paths",
                "static_coverage_unavailable_path",
                ("path", "reason"),
            ),
            (
                "unsupported_files",
                "static_coverage_unsupported",
                ("path", "reason"),
            ),
            (
                "excluded_test_files",
                "static_excluded_test_file",
                ("path", "reason"),
            ),
            (
                "out_of_scope_product_files",
                "static_out_of_scope_product",
                ("path", "reason"),
            ),
        )
        for _, prefix, _ in categories:
            empty[f"{prefix}_count"] = None
            empty[f"{prefix}_preview"] = []
            empty[f"{prefix}_truncated_count"] = None
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        checkpoint = self._store.get(identity, SimpleStage.STATIC_DONE)
        if checkpoint is None or checkpoint.status in {
            StageStatus.PENDING,
            StageStatus.RUNNING,
        }:
            return {**empty, "static_coverage_status": "PENDING"}
        try:
            if len(checkpoint.output_refs) < 2:
                raise ValueError("PUBLIC_STATIC_BUNDLE_MISSING")
            bundle_ref = checkpoint.output_refs[1]
            if (
                checkpoint.status is StageStatus.SUCCEEDED
                and run.static_bundle_ref is not None
                and run.static_bundle_ref != bundle_ref
            ):
                raise ValueError("PUBLIC_STATIC_BUNDLE_STALE")
            artifacts = SimpleArtifactRepository(self._config.data_dir, identity)
            bundle = json.loads(artifacts.read(bundle_ref))
            if not isinstance(bundle, dict) or any(
                bundle.get(key) != value
                for key, value in (
                    ("kind", "simple_static_fact_bundle"),
                    ("analysis_id", run.analysis_id),
                    ("workspace_id", run.workspace_id),
                    ("commit_id", run.commit_id),
                )
            ):
                raise ValueError("PUBLIC_STATIC_BUNDLE_INVALID")
            coverage_ref = StoredDataRef.model_validate(bundle["static_coverage_ref"])
            if checkpoint.status is StageStatus.SUCCEEDED:
                if (
                    run.static_coverage_ref is not None
                    and run.static_coverage_ref != coverage_ref
                ):
                    raise ValueError("PUBLIC_STATIC_COVERAGE_STALE")
            elif checkpoint.output_refs[0] != coverage_ref:
                raise ValueError("PUBLIC_STATIC_COVERAGE_EVIDENCE_MISMATCH")
            coverage = json.loads(artifacts.read(coverage_ref))
            if not isinstance(coverage, dict) or any(
                coverage.get(key) != value
                for key, value in (
                    ("kind", "simple_static_coverage_v1"),
                    ("analysis_id", run.analysis_id),
                    ("workspace_id", run.workspace_id),
                    ("commit_id", run.commit_id),
                )
            ):
                raise ValueError("PUBLIC_STATIC_COVERAGE_SCOPE_INVALID")
            fingerprint = coverage.get("fingerprint")
            if (
                not isinstance(fingerprint, str)
                or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
                or (
                    run.candidate_scope_fingerprint is not None
                    and fingerprint != run.candidate_scope_fingerprint
                )
            ):
                raise ValueError("PUBLIC_STATIC_COVERAGE_FINGERPRINT_INVALID")
            expected = coverage.get("expected_count")
            verified = coverage.get("verified_count")
            if (
                type(expected) is not int
                or type(verified) is not int
                or not 0 <= verified <= expected
            ):
                raise ValueError("PUBLIC_STATIC_COVERAGE_COUNT_INVALID")
            projected = dict(empty)
            for source_key, prefix, fields in categories:
                value = coverage.get(source_key)
                if value is None:
                    continue
                if not isinstance(value, list):
                    raise ValueError("PUBLIC_STATIC_COVERAGE_ROWS_INVALID")
                preview: list[dict[str, str]] = []
                for item in value:
                    if not isinstance(item, dict):
                        raise ValueError("PUBLIC_STATIC_COVERAGE_ROWS_INVALID")
                    row: dict[str, str] = {}
                    for field in fields:
                        cell = item.get(field)
                        if not isinstance(cell, str) or not cell:
                            raise ValueError("PUBLIC_STATIC_COVERAGE_ROWS_INVALID")
                        if field == "path":
                            if (
                                len(cell) > 512
                                or cell.startswith("/")
                                or ".." in PurePosixPath(cell).parts
                                or "\\" in cell
                                or ":" in cell
                                or any(
                                    ord(char) < 32 or ord(char) == 127 for char in cell
                                )
                            ):
                                raise ValueError("PUBLIC_STATIC_COVERAGE_PATH_INVALID")
                        elif (
                            re.fullmatch(
                                r"[A-Za-z0-9_.:+-]{1,128}"
                                if field == "reason"
                                else r"[A-Za-z0-9_.:-]{1,128}",
                                cell,
                            )
                            is None
                        ):
                            raise ValueError("PUBLIC_STATIC_COVERAGE_LABEL_INVALID")
                        row[field] = cell
                    if len(preview) < 20:
                        preview.append(row)
                projected[f"{prefix}_count"] = len(value)
                projected[f"{prefix}_preview"] = preview
                projected[f"{prefix}_truncated_count"] = max(0, len(value) - 20)
            if projected["static_coverage_gap_count"] != expected - verified:
                raise ValueError("PUBLIC_STATIC_COVERAGE_COUNT_INVALID")
            projected.update(
                {
                    "static_coverage_status": "AVAILABLE",
                    "static_coverage_digest": coverage_ref.content_hash,
                    "static_coverage_expected": expected,
                    "static_coverage_verified": verified,
                }
            )
            return projected
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
            return empty

    def result(self, analysis_id: str) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)
        run = self._store.require_analysis_run(exact)
        checkpoints = self._store.list_checkpoints(exact)
        stale_hypothesis_ids = stale_poc_hypothesis_ids(checkpoints)
        findings = (
            []
            if candidate_report_currentness_blocked(
                run,
                checkpoints,
                data_dir=self._config.data_dir,
                store=self._store,
            )
            else [
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.stage is SimpleStage.FINDING_DONE
                and checkpoint.output_refs
                and checkpoint.identity.hypothesis_id not in stale_hypothesis_ids
                and technical_gate_accepted(
                    self._store.get(checkpoint.identity, SimpleStage.TECH_GATE_DONE),
                    SimpleArtifactRepository(
                        self._config.data_dir, checkpoint.identity
                    ),
                )
            ]
        )
        display_store = FindingDisplayIdStore(self._store.database_path)
        eligible = {
            display_store.get_or_allocate(
                exact, checkpoint.output_refs[0]
            ): checkpoint.output_refs[0]
            for checkpoint in findings
        }
        group_count: int | None = None
        undetermined_count: int | None = None
        group_rows: tuple[dict[str, object], ...] = ()
        try:
            projection = project_current_finding_groups(
                run,
                checkpoints,
                eligible,
                data_dir=self._config.data_dir,
                database_path=self._store.database_path,
            )
            if projection.raw_count == len(findings):
                group_count = projection.visible_group_count
                undetermined_count = projection.undetermined_count
                group_rows = finding_group_rows(projection)
        except (OSError, ValueError, sqlite3.Error):
            # Raw Findings remain authoritative if optional grouping fails.
            pass
        return {
            **self.status(run.display_analysis_id),
            "hypothesis_count": (
                self._store.hypothesis_count(
                    CheckpointIdentity(
                        analysis_id=run.analysis_id,
                        workspace_id=run.workspace_id,
                        commit_id=run.commit_id,
                        hypothesis_id=None,
                    )
                )
                if run.candidate_pipeline_version in {1, 2}
                else len(run.hypothesis_ids)
            ),
            "finding_count": len(findings),
            "findings": list(eligible),
            "finding_group_count": group_count,
            "finding_group_undetermined_count": undetermined_count,
            "finding_groups": group_rows,
        }

    def poc(self, finding_id: str) -> str:
        identity, _finding_ref = self._finding_identity(finding_id)
        candidate = self._store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
        dynamic = self._store.require(identity, SimpleStage.POC_EXECUTION_DONE)
        if (
            stale_successful_poc(dynamic)
            or dynamic.validated_poc_ref is None
            or len(candidate.output_refs) < 2
        ):
            raise LookupError("VALIDATED_POC_NOT_FOUND")
        return (
            SimpleArtifactRepository(self._config.data_dir, identity)
            .read(candidate.output_refs[1])
            .decode("utf-8", errors="replace")
        )

    def report(self, finding_id: str) -> str:
        identity, finding_ref = self._finding_identity(finding_id)
        checkpoint = self._store.require(identity, SimpleStage.REPORT_DONE)
        if stale_successful_poc(
            self._store.get(identity, SimpleStage.POC_EXECUTION_DONE)
        ):
            raise LookupError("CURRENT_REPORT_NOT_FOUND")
        if not technical_gate_accepted(
            self._store.get(identity, SimpleStage.TECH_GATE_DONE),
            SimpleArtifactRepository(self._config.data_dir, identity),
        ):
            raise LookupError("CURRENT_REPORT_NOT_FOUND")
        if (
            not self._store.reusable(
                identity,
                SimpleStage.REPORT_DONE,
                checkpoint.input_refs,
            )
            or len(checkpoint.output_refs) < 2
        ):
            raise LookupError("CURRENT_REPORT_NOT_FOUND")
        artifacts = SimpleArtifactRepository(self._config.data_dir, identity)
        raw = artifacts.read(checkpoint.output_refs[1])
        try:
            run = self._store.require_analysis_run(identity.analysis_id)
        except LookupError:
            run = None
        if run is not None:
            try:
                artifacts.require_current_report_coverage(
                    checkpoint,
                    finding_ref,
                    run.static_coverage_ref,
                    run.static_disposition,
                )
            except (OSError, ValueError) as error:
                raise LookupError("CURRENT_REPORT_STALE") from error
        review = project_scope_review(
            self._store.get(identity, SimpleStage.SCOPE_GATE_DONE),
            artifacts,
            policy_snapshot_ref=run.policy_snapshot_ref if run else None,
            repository_url=run.repository if run else None,
        )
        return safe_public_report(raw, review).decode("utf-8", errors="strict")

    def export_report(self, finding_id: str) -> str:
        identity, _finding_ref = self._finding_identity(finding_id)
        checkpoint = self._store.require(identity, SimpleStage.REPORT_DONE)
        content = self.report(finding_id).encode("utf-8")
        if checkpoint.markdown_path is None:
            raise LookupError("CURRENT_REPORT_PATH_NOT_FOUND")
        report_path = Path(checkpoint.markdown_path).resolve()
        report_root = (self._config.data_dir / "reports").resolve()
        try:
            report_path.relative_to(self._config.data_dir.resolve())
            report_path.relative_to(report_root)
        except ValueError as error:
            raise ValueError("REPORT_PATH_OUTSIDE_DATA_DIR") from error
        original = SimpleArtifactRepository(self._config.data_dir, identity).read(
            checkpoint.output_refs[1]
        )
        if content != original:
            report_path = report_path.with_name(f"{report_path.stem}.restricted.md")
        relative = report_path.relative_to(self._config.data_dir.resolve())
        report_path.parent.mkdir(parents=True, exist_ok=True)
        if not report_path.exists() or report_path.read_bytes() != content:
            temporary = report_path.with_suffix(".md.next")
            temporary.write_bytes(content)
            os.replace(temporary, report_path)
        return relative.as_posix()

    def export_report_bundle(self, finding_id: str) -> str | None:
        """Expose only a current, verified local ZIP; keep older reports unchanged."""

        identity, finding_ref = self._finding_identity(finding_id)
        self.report(finding_id)
        try:
            prior = {
                item.stage: item
                for item in self._store.list_checkpoints(identity.analysis_id)
                if item.identity == identity
            }
            artifacts = SimpleArtifactRepository(self._config.data_dir, identity)
            try:
                run = self._store.require_analysis_run(identity.analysis_id)
            except LookupError:
                run = None
            review = project_scope_review(
                prior.get(SimpleStage.SCOPE_GATE_DONE),
                artifacts,
                policy_snapshot_ref=run.policy_snapshot_ref if run else None,
                repository_url=run.repository if run else None,
            )
            artifacts.verified_report_bundle(
                checkpoints=prior,
                finding_ref=finding_ref,
                display_id=finding_id,
                scope_status=str(review["status"]),
                public_projection=lambda body: safe_public_report(body, review),
            )
            report = prior[SimpleStage.REPORT_DONE]
            if report.markdown_path is None:
                return None
            return (
                Path("reports")
                / identity.analysis_id
                / Path(report.markdown_path).stem
                / "bundle.zip"
            ).as_posix()
        except (KeyError, OSError, ValueError):
            return None

    def _finding_identity(
        self,
        finding_id: str,
    ) -> tuple[CheckpointIdentity, StoredDataRef]:
        for exact in self._store.list_analysis_ids():
            try:
                finding_ref = FindingDisplayIdStore.resolve_existing(
                    self._store.database_path,
                    exact,
                    finding_id,
                )
            except (LookupError, ValueError):
                continue
            checkpoints = self._store.list_checkpoints(exact)
            try:
                run = self._store.require_analysis_run(exact)
            except LookupError:
                run = None
            if candidate_report_currentness_blocked(
                run,
                checkpoints,
                data_dir=self._config.data_dir,
                store=self._store,
            ):
                raise LookupError("FINDING_DISPLAY_ID_NOT_FOUND")
            for checkpoint in checkpoints:
                if (
                    checkpoint.stage is SimpleStage.FINDING_DONE
                    and finding_ref in checkpoint.output_refs
                ):
                    return checkpoint.identity, finding_ref
        raise LookupError("FINDING_DISPLAY_ID_NOT_FOUND")

    def _outcome(
        self,
        display_id: str,
        repository: str,
        commit: str,
    ) -> dict[str, object]:
        data = self.status(display_id)
        return {
            **data,
            "repository": redact_local_file_urls(repository),
            "commit": commit,
            "dashboard_url": f"http://127.0.0.1:8765/analyses/{display_id}",
        }


def build_public_simple_runtime(
    config_store: UserConfigStore | None = None,
) -> PublicSimpleRuntimeApplication:
    store = config_store or UserConfigStore()
    config = store.load()
    if not config.setup_ready:
        raise ValueError("SETUP_NOT_READY")
    profile = load_simple_execution_profile(config.profile_path)
    if profile.data_dir != config.data_dir:
        raise ValueError("USER_CONFIG_PROFILE_MISMATCH")
    return PublicSimpleRuntimeApplication(config, profile)


__all__ = [
    "PublicSimpleRuntimeApplication",
    "SimpleClientFactory",
    "build_analysis_application",
    "build_public_simple_runtime",
    "list_cursor_models",
]
