"""Composition root for the public single-process SimpleRuntime."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sastsimi.composition.local_claude_binding import build_local_claude_binding
from sastsimi.composition.local_codex_binding import build_local_codex_binding
from sastsimi.config.local_evaluation_profile import (
    LocalClaudeSubscriptionSettings,
    LocalCodexSubscriptionSettings,
)
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    UserConfig,
    UserConfigStore,
    load_simple_execution_profile,
)
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.public_commands import PublicCommandApplication
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.progress.projector import ProgressProjector
from sastsimi.providers.claude_subscription import ClaudeCliProcessRunner
from sastsimi.providers.codex_subscription import CodexCliProcessRunner
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.runtime.system_support import SystemClock, UUIDIds
from sastsimi.sandbox.docker_adapter import DockerAdapter
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
from sastsimi.simple_runtime.call_queue import CallQueue
from sastsimi.simple_runtime.models import CheckpointIdentity, SimpleStage
from sastsimi.simple_runtime.portable_docker import (
    DirectEnvironmentPreparer,
    PortableContainerFactory,
    PortableDockerRuntime,
)
from sastsimi.simple_runtime.provider import (
    SimpleClaudeClient,
    SimpleCodexClient,
    SimpleOpenAIClient,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.stages import build_stage_handlers
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _call_timeout_ms(profile: SimpleExecutionProfile) -> int:
    """Return the per-call ceiling the operator's elapsed budget allows.

    One stage must not be able to consume the whole run, so the share is
    bounded well below ``max_elapsed_seconds`` while still clearing the
    three-minute default that a large static bundle routinely exceeds.
    """

    return max(180_000, min(profile.max_elapsed_seconds * 1000 // 8, 1_800_000))


def _codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def _child_failure_sink(data_dir: Path) -> Callable[[str, int, bytes], None]:
    """Keep a dead child's exit code and stderr tail where an operator can read it.

    The normalized result stays free of child text; this file is local only,
    and without it a failed call is an unexplained ``FAILED``.
    """

    directory = data_dir / "diagnostics"

    def record(invocation_id: str, returncode: int, stderr: bytes) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        target = directory / f"{stamp}-{invocation_id}.txt"
        target.write_bytes(
            f"exit={returncode}\n".encode() + b"--- stderr tail ---\n" + stderr
        )

    return record


def _claude_config_dir() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured).expanduser() if configured else Path.home() / ".claude"


class SimpleClientFactory:
    def __init__(self, profile: SimpleExecutionProfile) -> None:
        self._profile = profile
        # One queue for the whole run.  A client is built per hypothesis, so a
        # ceiling that lived on the client was multiplied by however many
        # hypotheses were in flight.
        self._queue = CallQueue(max_concurrent=profile.max_parallel_calls)

    @property
    def queue(self) -> CallQueue:
        return self._queue

    def __call__(
        self,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
        *,
        deep: bool = False,
    ) -> SimpleClaudeClient | SimpleCodexClient | SimpleOpenAIClient:
        model = self._profile.model_for(deep=deep)
        if self._profile.auth_mode == "API_KEY":
            return SimpleOpenAIClient(
                credential_ref=self._profile.credential_ref,
                model=model,
            )
        scope = PlannedRunScope(
            analysis_id=AnalysisId(identity.analysis_id),
            workspace_id=WorkspaceId(identity.workspace_id),
            commit_id=CommitId(identity.commit_id),
            repository_ref="simple-runtime",
        )
        if self._profile.provider.casefold() == "claude":
            return self._claude(scope, artifacts, model)
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

    def _claude(
        self,
        scope: PlannedRunScope,
        artifacts: SimpleArtifactRepository,
        model: str,
    ) -> SimpleClaudeClient:
        try:
            tool = self._profile.tools["claude"]
        except KeyError:
            raise ValueError("CLAUDE_NOT_CONFIGURED") from None
        binding = build_local_claude_binding(
            settings=LocalClaudeSubscriptionSettings(
                provider_profile_key=self._profile.provider_profile_ref,
                executable_path=tool.executable_path,
                executable_sha256=tool.executable_sha256,
                claude_config_dir=_claude_config_dir(),
                client_version=tool.version,
                model=model,
            ),
            scope=scope,
            artifacts=artifacts.artifacts,
            ids=UUIDIds(),
            clock=SystemClock(),
        )
        provider_ref = reference(binding.provider)
        if not isinstance(provider_ref, StoredDataRef):
            raise ValueError("SIMPLE_RUNTIME_PROVIDER_REFERENCE_INVALID")
        return SimpleClaudeClient(
            runner=ClaudeCliProcessRunner(
                binding=binding.binding,
                diagnostics=_child_failure_sink(self._profile.data_dir),
            ),
            provider_profile_ref=provider_ref,
            model=model,
            queue=self._queue,
        )


def _ast_facts_loader(
    artifacts: SimpleArtifactRepository, static: StaticBootstrapResult
) -> Callable[[], Sequence[Any]]:
    """Read the parsed facts the first time an agent actually asks for them.

    They are three megabytes for a mid-sized repository and most runs never
    need them, so the read is deferred and then kept.
    """

    cached: list[Sequence[Any]] = []

    def load() -> Sequence[Any]:
        if cached:
            return cached[0]
        facts: Sequence[Any] = ()
        try:
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            for raw in bundle.get("tool_result_refs", ()):
                document = json.loads(artifacts.read(StoredDataRef.model_validate(raw)))
                if document.get("kind") == "simple_python_ast":
                    facts = document.get("facts") or ()
                    break
        except (OSError, ValueError, KeyError):
            facts = ()
        cached.append(facts)
        return facts

    return load


def build_analysis_application(
    config: UserConfig,
    profile: SimpleExecutionProfile,
) -> SimpleAnalysisApplication:
    data_dir = config.data_dir
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    client_factory = SimpleClientFactory(profile)
    docker = PortableDockerRuntime(profile)
    # Shared across every hypothesis, because the host has one set of
    # containers however many hypotheses are in flight.
    container_slots = asyncio.Semaphore(profile.max_parallel_containers)

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
        return SimpleRuntimeRunner(
            runtime_store,
            build_stage_handlers(
                client=client,
                artifacts=artifacts,
                docker=cast(DockerAdapter, docker),
                containers=PortableContainerFactory(docker),
                environments=environments,
                store=runtime_store,
                workspace=static.workspace_path,
                ast_facts=_ast_facts_loader(artifacts, static),
                max_parallel_containers=profile.max_parallel_containers,
                container_slots=container_slots,
                # A stage that exceeds its per-call ceiling is blocked for the
                # whole run, so the operator's elapsed budget has to reach the
                # LLM calls too, not only the tool subprocesses.
                call_timeout_ms=_call_timeout_ms(profile),
                poc_timeout_ms=_call_timeout_ms(profile),
            ),
        )

    return SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=DirectStaticBootstrap(profile=profile),
        hypothesis_bootstrap=DirectHypothesisBootstrap(
            data_dir=data_dir,
            client_factory=client_factory,
            call_timeout_ms=_call_timeout_ms(profile),
            feed=profile.hypothesis_feed,
        ),
        runner_factory=runner_factory,
        max_parallel_hypotheses=profile.max_parallel_hypotheses,
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
        return self._outcome(
            outcome.display_analysis_id,
            run.repository,
            run.commit_id,
        )

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
        return self._outcome(
            outcome.display_analysis_id,
            stored.repository,
            stored.commit_id,
        )

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
        }

    def result(self, analysis_id: str) -> dict[str, object]:
        exact = self._display.resolve(analysis_id)
        run = self._store.require_analysis_run(exact)
        checkpoints = self._store.list_checkpoints(exact)
        findings = [
            checkpoint
            for checkpoint in checkpoints
            if checkpoint.stage is SimpleStage.FINDING_DONE and checkpoint.output_refs
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
        if (
            not self._store.reusable(
                identity,
                SimpleStage.REPORT_DONE,
                checkpoint.input_refs,
            )
            or len(checkpoint.output_refs) < 2
        ):
            raise LookupError("CURRENT_REPORT_NOT_FOUND")
        return (
            SimpleArtifactRepository(self._config.data_dir, identity)
            .read(checkpoint.output_refs[1])
            .decode("utf-8", errors="strict")
        )

    def export_report(self, finding_id: str) -> str:
        identity, _finding_ref = self._finding_identity(finding_id)
        checkpoint = self._store.require(identity, SimpleStage.REPORT_DONE)
        content = self.report(finding_id).encode("utf-8")
        if checkpoint.markdown_path is None:
            raise LookupError("CURRENT_REPORT_PATH_NOT_FOUND")
        report_path = Path(checkpoint.markdown_path).resolve()
        report_root = (self._config.data_dir / "reports").resolve()
        try:
            relative = report_path.relative_to(self._config.data_dir.resolve())
            report_path.relative_to(report_root)
        except ValueError as error:
            raise ValueError("REPORT_PATH_OUTSIDE_DATA_DIR") from error
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
]
