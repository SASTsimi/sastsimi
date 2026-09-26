"""Composition root for the public single-process SimpleRuntime."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from pathlib import Path
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
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.policy.adapters.official_http import (
    PinnedHttpsTransport,
    resolve_public_addresses,
)
from sastsimi.ports.public_commands import PublicCommandApplication
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.progress.projector import ProgressProjector
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
from sastsimi.simple_runtime.gate_guard import technical_gate_accepted
from sastsimi.simple_runtime.github_policy import GitHubPolicyDiscovery
from sastsimi.simple_runtime.models import CheckpointIdentity, SimpleStage
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
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.scope_policy import (
    project_scope_review,
    safe_public_report,
)
from sastsimi.simple_runtime.stages import build_stage_handlers
from sastsimi.simple_runtime.store import SimpleCheckpointStore


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
            profile.data_dir / "db" / "sastsimi.sqlite3"
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
            runner=CodexCliProcessRunner(binding=binding.binding),
            provider_profile_ref=provider_ref,
            model=model,
        )


def build_analysis_application(
    config: UserConfig,
    profile: SimpleExecutionProfile,
) -> SimpleAnalysisApplication:
    data_dir = config.data_dir
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
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
        ),
        runner_factory=runner_factory,
        recovery_factory=recovery_factory,
        max_parallel_hypotheses=profile.max_parallel_hypotheses,
        max_elapsed_seconds=profile.max_elapsed_seconds,
    )


class PublicSimpleRuntimeApplication(PublicCommandApplication):
    def __init__(self, config: UserConfig, profile: SimpleExecutionProfile) -> None:
        self._config = config
        self._profile = profile
        self._store = SimpleCheckpointStore(config.data_dir / "db" / "sastsimi.sqlite3")
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
                    current = ProgressProjector(self._store).snapshot(started[0])
                except LookupError:
                    current = None
                if current is not None and current != last:
                    callback(current)
                    last = current
            await asyncio.sleep(0.2)
        outcome = await task
        if started:
            current = ProgressProjector(self._store).snapshot(started[0])
            if current != last:
                callback(current)
        return outcome

    def status(self, analysis_id: str) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)
        snapshot = ProgressProjector(self._store).snapshot(exact)
        run = self._store.require_analysis_run(exact)
        return {
            "analysis_id": run.display_analysis_id,
            "exact_analysis_id": exact,
            "status": snapshot.status,
            "percent": snapshot.percent,
            "completed_units": snapshot.completed_units,
            "known_units": snapshot.known_units,
            "current_stage": snapshot.current_stage,
            "current_hypothesis_id": snapshot.current_hypothesis_id,
            "attempt_number": snapshot.attempt_number,
            "attempt_limit": snapshot.attempt_limit,
            "error_code": snapshot.error_code,
            "inconclusive_hypothesis_count": snapshot.inconclusive_hypothesis_count,
            "rejected_hypothesis_count": snapshot.rejected_hypothesis_count,
        }

    def result(self, analysis_id: str) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)
        run = self._store.require_analysis_run(exact)
        checkpoints = self._store.list_checkpoints(exact)
        findings = [
            checkpoint
            for checkpoint in checkpoints
            if checkpoint.stage is SimpleStage.FINDING_DONE
            and checkpoint.output_refs
            and technical_gate_accepted(
                self._store.get(checkpoint.identity, SimpleStage.TECH_GATE_DONE),
                SimpleArtifactRepository(self._config.data_dir, checkpoint.identity),
            )
        ]
        return {
            **self.status(run.display_analysis_id),
            "hypothesis_count": len(run.hypothesis_ids),
            "finding_count": len(findings),
            "findings": [
                FindingDisplayIdStore(self._store.database_path).get_or_allocate(
                    exact,
                    checkpoint.output_refs[0],
                )
                for checkpoint in findings
            ],
        }

    def poc(self, finding_id: str) -> str:
        identity, _finding_ref = self._finding_identity(finding_id)
        candidate = self._store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
        dynamic = self._store.require(identity, SimpleStage.POC_EXECUTION_DONE)
        if dynamic.validated_poc_ref is None or len(candidate.output_refs) < 2:
            raise LookupError("VALIDATED_POC_NOT_FOUND")
        return (
            SimpleArtifactRepository(self._config.data_dir, identity)
            .read(candidate.output_refs[1])
            .decode("utf-8", errors="replace")
        )

    def report(self, finding_id: str) -> str:
        identity, _finding_ref = self._finding_identity(finding_id)
        checkpoint = self._store.require(identity, SimpleStage.REPORT_DONE)
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
            for checkpoint in self._store.list_checkpoints(exact):
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
            "repository": repository,
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
