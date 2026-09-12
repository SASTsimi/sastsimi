"""Official Codex CLI adapter for ChatGPT subscription-authenticated calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    Environment,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult

from .base import (
    Clock,
    CodexProcessRequest,
    CodexProcessResult,
    CodexProcessRunner,
    InvocationResultBuilder,
    NormalizedProviderResult,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
    ProviderProbeRunner,
    ProviderSessionStore,
    ResolvedPromptInput,
)
from .normalization import (
    NormalizedFailure,
    codex_failure,
    normalize_codex_exception,
)

_MAX_EVENT_STREAM_BYTES = 1_048_576
_MAX_STDERR_BYTES = 65_536
_MAX_FINAL_MESSAGE_BYTES = 1_048_576
_TREE_KILLER_TIMEOUT_SECONDS = 2.0
_ARRAY_ENVELOPE_KEY = "items"
_CHATGPT_LOGIN_STATUS = "Logged in using ChatGPT"
_RATE_LIMIT_MARKERS = (
    b"rate limit",
    b"rate_limit",
    b"too many requests",
    b"usage limit",
    b"quota",
    b"429",
)
_AUTH_FAILURE_MARKERS = (
    b"not logged in",
    b"authentication required",
    b"unauthorized",
    b"invalid authentication",
    b"login required",
    b"401",
)
_CHILD_ENVIRONMENT_ALLOWLIST = (
    "CODEX_HOME",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
)
_DISABLED_FEATURES = (
    "apps",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "code_mode",
    "code_mode_host",
    "computer_use",
    "current_time_reminder",
    "deferred_executor",
    "enable_mcp_apps",
    "exec_permission_approvals",
    "executor_capability_discovery",
    "external_agent_memory_import",
    "goals",
    "hooks",
    "image_generation",
    "in_app_browser",
    "in_app_local_automation",
    "memories",
    "multi_agent",
    "multi_agent_v2",
    "personality",
    "plugins",
    "recommended_plugins",
    "remote_plugin",
    "request_permissions_tool",
    "shell_snapshot",
    "shell_snapshot_v2",
    "shell_tool",
    "skill_mcp_dependency_install",
    "skill_search",
    "sleep_tool",
    "standalone_web_search",
    "terminal_visualization_instructions",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "unified_exec",
    "use_agent_identity",
    "view_image",
    "web_search_cached",
    "web_search_request",
    "workspace_dependencies",
)
_CONFIG_OVERRIDES = (
    'forced_login_method="chatgpt"',
    'model_provider="openai"',
    'approval_policy="never"',
    'web_search="disabled"',
    'history.persistence="none"',
    "hide_agent_reasoning=true",
    "show_raw_agent_reasoning=false",
    "project_doc_max_bytes=0",
    "project_root_markers=[]",
    'shell_environment_policy.inherit="none"',
    "mcp_servers={}",
    "hooks={}",
)


class ProviderExecutableBindingError(RuntimeError):
    """The official client no longer matches its approved executable binding."""


class _ProcessTreeTerminationError(RuntimeError):
    """The child exited but complete process-tree termination was not confirmed."""


@dataclass(frozen=True)
class ApprovedCodexExecutable:
    """Exact composition-time approval for one official Codex CLI binary."""

    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if (
            not self.path.is_absolute()
            or self.path.is_symlink()
            or len(self.sha256) != 64
            or self.sha256 != self.sha256.lower()
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("INVALID_CODEX_EXECUTABLE_BINDING")


@dataclass(frozen=True)
class ApprovedCodexExecutionBinding:
    """Exact approved profile, client boundary, executable and runtime scope."""

    provider_profile: ProviderProfile
    client_execution_profile: ClientExecutionProfile
    executable: ApprovedCodexExecutable
    codex_home: Path
    runtime_environment: Environment

    def __post_init__(self) -> None:
        _validate_execution_binding(self)


@dataclass(frozen=True)
class _ChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CodexCliProcessRunner:
    """Run a hash-pinned official ``codex exec`` in a disposable boundary."""

    def __init__(
        self,
        *,
        binding: ApprovedCodexExecutionBinding,
    ) -> None:
        self.binding = binding
        self.executable = binding.executable
        self.codex_home = binding.codex_home
        _validate_execution_binding(self.binding)
        self.verify_executable()

    def verify_executable(self) -> None:
        """Recheck the immutable approval immediately before every spawn."""
        try:
            if (
                not self.executable.path.is_file()
                or self.executable.path.is_symlink()
                or self.executable.path.resolve(strict=True) != self.executable.path
                or not self.codex_home.is_dir()
                or self.codex_home.is_symlink()
                or self.codex_home.resolve(strict=True) != self.codex_home
            ):
                raise OSError
            digest = _sha256_file(self.executable.path)
        except OSError:
            raise ProviderExecutableBindingError from None
        if digest != self.executable.sha256:
            raise ProviderExecutableBindingError

    def verify_binding(self, request: CodexProcessRequest) -> None:
        """Revalidate exact approved records and request identity before a call."""
        _validate_process_request(request)
        _validate_execution_binding(self.binding)
        if (
            request.provider_profile_ref != reference(self.binding.provider_profile)
            or request.model != self.binding.provider_profile.model
        ):
            raise ProviderInputMismatchError
        self.verify_executable()

    def child_environment(self, source: Mapping[str, str]) -> dict[str, str]:
        """Build a small allowlisted environment with no ambient credentials."""
        environment = {"CODEX_HOME": str(self.codex_home)}
        allowed = (
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        )
        source_by_upper = {key.upper(): value for key, value in source.items()}
        for name in allowed:
            value = source_by_upper.get(name)
            if value:
                environment[name] = value
        return environment

    def execution_argv(
        self,
        request: CodexProcessRequest,
        work_directory: Path,
        schema_path: Path,
        output_path: Path,
    ) -> tuple[str, ...]:
        """Return the fixed no-tools invocation; prompt bytes are stdin-only."""
        _validate_process_request(request)
        if not all(
            path.is_absolute() for path in (work_directory, schema_path, output_path)
        ):
            raise ValueError("CODEX_BOUNDARY_PATH_MUST_BE_ABSOLUTE")
        arguments = [
            str(self.executable.path),
            "exec",
            "--model",
            request.model,
            "--sandbox",
            "read-only",
            "--cd",
            str(work_directory),
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--color",
            "never",
            "--json",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
        ]
        for override in _CONFIG_OVERRIDES:
            arguments.extend(("--config", override))
        for feature in _DISABLED_FEATURES:
            arguments.extend(("--disable", feature))
        arguments.extend(("--enable", "skip_host_skill_discovery", "-"))
        return tuple(arguments)

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        try:
            self.verify_binding(request)
            environment = self.child_environment(os.environ)
            with tempfile.TemporaryDirectory(prefix="sastsimi-codex-") as temporary:
                temporary_root = Path(temporary).resolve()
                work_directory = temporary_root / "work"
                control_directory = temporary_root / "control"
                auth_check_directory = temporary_root / "auth-check"
                control_directory.mkdir()
                auth_check_directory.mkdir()
                schema_path = control_directory / "schema.json"
                output_path = control_directory / "last-message.json"
                schema = _strict_json(request.output_schema, ProviderInputMismatchError)
                if not isinstance(schema, dict):
                    raise ProviderInputMismatchError
                schema_path.write_bytes(canonical_bytes(_codex_output_schema(schema)))
                async with asyncio.timeout(request.timeout_ms / 1_000):
                    version = await self._run_child(
                        (str(self.executable.path), "--version"),
                        stdin=None,
                        cwd=auth_check_directory,
                        environment=environment,
                    )
                    _require_codex_cli_version(
                        version, self.binding.provider_profile.client_version
                    )
                    login = await self._run_child(
                        (
                            str(self.executable.path),
                            "login",
                            "status",
                        ),
                        stdin=None,
                        cwd=auth_check_directory,
                        environment=environment,
                    )
                    if login.returncode != 0:
                        return CodexProcessResult(
                            _classify_child_failure(login), None, None
                        )
                    if not _is_exact_chatgpt_login_status(login):
                        return CodexProcessResult("AUTH_REQUIRED", None, None)
                    self.verify_executable()
                    work_directory.mkdir()
                    execution = await self._run_child(
                        self.execution_argv(
                            request,
                            work_directory,
                            schema_path,
                            output_path,
                        ),
                        stdin=request.prompt,
                        cwd=work_directory,
                        environment=environment,
                    )
                if execution.returncode != 0:
                    return CodexProcessResult(
                        _classify_child_failure(execution), None, None
                    )
                session_id = _validated_session_id(execution.stdout)
                try:
                    if not output_path.is_file():
                        raise ProviderInvalidOutputError
                    if output_path.stat().st_size > _MAX_FINAL_MESSAGE_BYTES:
                        raise ProviderInvalidOutputError
                    final_message = output_path.read_bytes()
                except OSError as error:
                    raise ProviderInvalidOutputError from error
                if not final_message:
                    raise ProviderInvalidOutputError
                return CodexProcessResult("SUCCEEDED", final_message, session_id)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            return CodexProcessResult("TIMED_OUT", None, None)
        except ProviderInvalidOutputError:
            return CodexProcessResult("INVALID_OUTPUT", None, None)
        except (ProviderExecutableBindingError, ProviderInputMismatchError, OSError):
            return CodexProcessResult("FAILED", None, None)

    async def _run_child(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> _ChildResult:
        self.verify_executable()
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                stdin=(
                    asyncio.subprocess.DEVNULL
                    if stdin is None
                    else asyncio.subprocess.PIPE
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=dict(environment),
                creationflags=_windows_creation_flags(),
                start_new_session=os.name != "nt",
            )
        )
        try:
            process = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            process = await asyncio.shield(spawn_task)
            await _terminate_process_tree(process)
            raise
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(
            _drain_bounded(process.stdout, _MAX_EVENT_STREAM_BYTES)
        )
        stderr_task = asyncio.create_task(
            _drain_bounded(process.stderr, _MAX_STDERR_BYTES)
        )
        stdin_task = (
            asyncio.create_task(_write_stdin(process, stdin))
            if stdin is not None
            else None
        )
        try:
            returncode = await process.wait()
            if stdin_task is not None:
                await stdin_task
            return _ChildResult(
                returncode,
                await stdout_task,
                await stderr_task,
            )
        except asyncio.CancelledError:
            await _terminate_process_tree(process)
            raise
        finally:
            if process.returncode is None:
                await _terminate_process_tree(process)
            for task in (stdin_task, stdout_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (stdin_task, stdout_task, stderr_task) if task),
                return_exceptions=True,
            )


class CodexSubscriptionAdapter:
    """Translate one exact NEW-session request through an official Codex client."""

    def __init__(
        self,
        *,
        provider_profile_ref: StoredDataRef,
        model: str,
        prompt_resolver: PromptInputResolver,
        process_runner: CodexProcessRunner,
        session_store: ProviderSessionStore,
        output_schema_validator: OutputSchemaValidator,
        result_builder: InvocationResultBuilder,
        clock: Clock,
        probe_runner: ProviderProbeRunner | None = None,
    ) -> None:
        self.provider_profile_ref = provider_profile_ref
        self.model = model
        self.prompt_resolver = prompt_resolver
        self.process_runner = process_runner
        self.session_store = session_store
        self.output_schema_validator = output_schema_validator
        self.result_builder = result_builder
        self.clock = clock
        self.probe_runner = probe_runner
        self._active: dict[str, asyncio.Task[LLMInvocationResult]] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._active_lock = asyncio.Lock()

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        if self.probe_runner is not None:
            observed = await self.probe_runner.run(candidate, self)
            return CapabilityProbeResult(
                evidence=_fail_unobservable_model_test(observed.evidence)
            )
        evidence = candidate.model_copy(
            update={
                "tests": tuple(
                    test.model_copy(
                        update={
                            "result": "FAIL",
                            "safe_summary": (
                                "Codex subscription probe runner is not configured"
                            ),
                        }
                    )
                    for test in candidate.tests
                )
            }
        )
        return CapabilityProbeResult(evidence=evidence)

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        cancel_event = asyncio.Event()
        async with self._active_lock:
            if request.llm_call_id in self._active:
                return self._failed_before_call(request)
            current = asyncio.create_task(self._invoke_active(request, cancel_event))
            self._active[request.llm_call_id] = current
            self._cancel_events[request.llm_call_id] = cancel_event
        try:
            return await current
        finally:
            async with self._active_lock:
                if self._active.get(request.llm_call_id) is current:
                    del self._active[request.llm_call_id]
                    self._cancel_events.pop(request.llm_call_id, None)

    async def _invoke_active(
        self,
        request: LLMInvocationRequest,
        cancel_event: asyncio.Event,
    ) -> LLMInvocationResult:
        started_at = self.clock.now()
        started_ms = self.clock.monotonic_ms()
        work_task = asyncio.create_task(
            self._invoke_once(
                request,
                started_at=started_at,
                started_ms=started_ms,
                cancel_event=cancel_event,
            )
        )
        try:
            done, _pending = await asyncio.wait(
                (work_task,), timeout=request.timeout_ms / 1_000
            )
            if done:
                try:
                    return await work_task
                except _ProcessTreeTerminationError:
                    normalized = codex_failure("FAILED")
            else:
                cleanup_error = await _cancel_and_wait(work_task)
                normalized = codex_failure(
                    "FAILED" if cleanup_error is not None else "TIMED_OUT"
                )
        except asyncio.CancelledError:
            cleanup_error = await _cancel_and_wait(work_task)
            normalized = codex_failure(
                "FAILED" if cleanup_error is not None else "CANCELLED"
            )
        return self._build_checked(
            request,
            self._failure_outcome(
                request,
                normalized,
                started_at=started_at,
                started_ms=started_ms,
            ),
        )

    async def _invoke_once(
        self,
        request: LLMInvocationRequest,
        *,
        started_at: datetime,
        started_ms: int,
        cancel_event: asyncio.Event,
    ) -> LLMInvocationResult:
        try:
            resolved, schema = await self._prepare(request)
            process_result = await self.process_runner.execute(
                CodexProcessRequest(
                    invocation_id=request.llm_call_id,
                    provider_profile_ref=request.provider_profile_ref,
                    model=request.model,
                    prompt=resolved.rendered_prompt_bytes,
                    output_schema=resolved.output_schema_bytes,
                    timeout_ms=request.timeout_ms,
                )
            )
            if process_result.status != "SUCCEEDED":
                outcome = self._failure_outcome(
                    request,
                    codex_failure(process_result.status),
                    started_at=started_at,
                    started_ms=started_ms,
                )
            else:
                outcome = await self._success_outcome(
                    request,
                    process_result,
                    resolved=resolved,
                    schema=schema,
                    started_at=started_at,
                    started_ms=started_ms,
                    cancel_event=cancel_event,
                )
        except asyncio.CancelledError:
            raise
        except _ProcessTreeTerminationError:
            raise
        except Exception as error:
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                raise _ProcessTreeTerminationError from None
            outcome = self._failure_outcome(
                request,
                normalize_codex_exception(error),
                started_at=started_at,
                started_ms=started_ms,
            )
        return self._build_checked(request, outcome)

    async def _success_outcome(
        self,
        request: LLMInvocationRequest,
        process_result: CodexProcessResult,
        *,
        resolved: ResolvedPromptInput,
        schema: dict[str, JsonValue],
        started_at: datetime,
        started_ms: int,
        cancel_event: asyncio.Event,
    ) -> NormalizedProviderResult:
        final_message = process_result.final_message
        provider_session_id = process_result.provider_session_id
        if (
            not isinstance(final_message, bytes)
            or not isinstance(provider_session_id, str)
            or not provider_session_id.strip()
        ):
            raise ProviderInvalidOutputError
        provider_output = _strict_json(final_message, ProviderInvalidOutputError)
        parsed = _unwrap_codex_output(provider_output, schema)
        if not isinstance(parsed, (dict, list)):
            raise ProviderInvalidOutputError
        raw_output = canonical_bytes(parsed)
        try:
            validated_output = self.output_schema_validator.validate(
                raw_output,
                schema=schema,
                output_schema=resolved.output_schema,
                request=request,
            )
            if canonical_bytes(validated_output) != raw_output:
                raise ProviderInvalidOutputError
        except ProviderInvalidOutputError:
            raise
        except Exception as error:
            raise ProviderInvalidOutputError from error
        self._raise_if_cancel_requested(cancel_event)
        session_ref = await self.session_store.register_response(
            provider_session_id, request.llm_call_id
        )
        self._raise_if_cancel_requested(cancel_event)
        if not session_ref.strip():
            raise ProviderInvalidOutputError
        return NormalizedProviderResult(
            status="SUCCEEDED",
            provider="OPENAI",
            model=request.model,
            actual_session_mode="NEW",
            session_ref=session_ref,
            response_text=raw_output.decode("utf-8"),
            parsed_output=parsed,
            validated_output=validated_output,
            usage=None,
            started_at=started_at,
            finished_at=self.clock.now(),
            elapsed_ms=max(0, self.clock.monotonic_ms() - started_ms),
            safe_error=None,
        )

    async def _prepare(
        self, request: LLMInvocationRequest
    ) -> tuple[ResolvedPromptInput, dict[str, JsonValue]]:
        if (
            request.provider_profile_ref != self.provider_profile_ref
            or request.model != self.model
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
        ):
            raise ProviderInputMismatchError
        resolved = await self.prompt_resolver.resolve(request)
        try:
            payload_ref = reference(resolved.payload)
            output_schema_ref = reference(resolved.output_schema)
        except (TypeError, ValueError) as error:
            raise ProviderInputMismatchError from error
        payload = resolved.payload
        if (
            not isinstance(payload_ref, StoredDataRef)
            or payload_ref != request.prompt_payload_ref
            or not isinstance(output_schema_ref, StoredDataRef)
            or output_schema_ref != request.output_schema_ref
            or payload.registry_entry_ref != request.prompt_registry_entry_ref
            or payload.prompt_key != request.prompt_key
            or payload.agent_role != request.agent_role
            or payload.task_kind != request.task_kind
            or payload.purpose != request.purpose
            or payload.template_ref != request.prompt_template_ref
            or payload.template_version != request.prompt_template_version
            or payload.output_schema_ref != request.output_schema_ref
            or tuple(binding.source_ref for binding in payload.context_bindings)
            != request.context_refs
            or request.output_schema_ref.data_kind != "output_schema_spec"
            or any(
                getattr(payload.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
        ):
            raise ProviderInputMismatchError
        if (
            _sha256(resolved.template_bytes) != payload.template_ref.content_hash
            or _sha256(resolved.output_schema_bytes)
            != resolved.output_schema.schema_artifact_ref.content_hash
            or _sha256(resolved.rendered_prompt_bytes)
            != payload.rendered_prompt_ref.content_hash
        ):
            raise ProviderInputMismatchError
        if len(resolved.projected_contexts) != len(payload.context_bindings):
            raise ProviderInputMismatchError
        rendered_bindings: list[dict[str, JsonValue]] = []
        for binding, context in zip(
            payload.context_bindings, resolved.projected_contexts, strict=True
        ):
            if (
                binding.trust_class != "UNTRUSTED_DATA"
                or context.slot != binding.slot
                or context.projected_data_ref != binding.projected_data_ref
                or _sha256(context.data) != binding.projected_data_ref.content_hash
            ):
                raise ProviderInputMismatchError
            value = _strict_json(context.data, ProviderInputMismatchError)
            if canonical_bytes(value) != context.data:
                raise ProviderInputMismatchError
            rendered_bindings.append(
                cast(
                    dict[str, JsonValue],
                    {
                        "slot": binding.slot,
                        "trust_class": "UNTRUSTED_DATA",
                        "sha256": _sha256(context.data),
                        "data": value,
                    },
                )
            )
        data_section = canonical_bytes({"bindings": rendered_bindings})
        data_section = data_section.replace(b"<", b"\\u003c").replace(b">", b"\\u003e")
        expected_rendered = (
            resolved.template_bytes
            + b"\n<UNTRUSTED_DATA>\n"
            + data_section
            + b"\n</UNTRUSTED_DATA>\n"
        )
        schema = _strict_json(resolved.output_schema_bytes, ProviderInputMismatchError)
        if (
            expected_rendered != resolved.rendered_prompt_bytes
            or not isinstance(schema, dict)
            or canonical_bytes(schema) != resolved.output_schema_bytes
            or request.output_schema.encode("utf-8") != resolved.output_schema_bytes
            or not resolved.template_bytes.strip()
        ):
            raise ProviderInputMismatchError
        return resolved, schema

    def _failure_outcome(
        self,
        request: LLMInvocationRequest,
        normalized: NormalizedFailure,
        *,
        started_at: datetime,
        started_ms: int,
    ) -> NormalizedProviderResult:
        return NormalizedProviderResult(
            status=normalized.status,
            provider="OPENAI",
            model=request.model,
            actual_session_mode="NEW",
            session_ref=None,
            response_text=None,
            parsed_output=None,
            validated_output=None,
            usage=None,
            started_at=started_at,
            finished_at=self.clock.now(),
            elapsed_ms=max(0, self.clock.monotonic_ms() - started_ms),
            safe_error=normalized.safe_error,
        )

    def _failed_before_call(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        now = self.clock.now()
        return self._build_checked(
            request,
            NormalizedProviderResult(
                status="FAILED",
                provider="OPENAI",
                model=request.model,
                actual_session_mode="NEW",
                session_ref=None,
                response_text=None,
                parsed_output=None,
                validated_output=None,
                usage=None,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                safe_error="FAILED: duplicate Codex invocation is active",
            ),
        )

    def _build_checked(
        self, request: LLMInvocationRequest, outcome: NormalizedProviderResult
    ) -> LLMInvocationResult:
        expected_success = outcome.status == "SUCCEEDED"
        if expected_success != (
            outcome.response_text is not None
            and outcome.parsed_output is not None
            and outcome.validated_output is not None
            and outcome.session_ref is not None
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        result = LLMInvocationResult.model_validate(
            self.result_builder.build(request, outcome)
        )
        if (
            result.meta.record_type != "llm_invocation_result"
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.status != outcome.status
            or result.provider != "OPENAI"
            or result.model != request.model
            or result.actual_session_mode != "NEW"
            or result.session_ref != outcome.session_ref
            or result.usage != outcome.usage
            or result.started_at != outcome.started_at
            or result.finished_at != outcome.finished_at
            or result.elapsed_ms != outcome.elapsed_ms
            or result.safe_error != outcome.safe_error
            or (result.response_ref is not None) != expected_success
            or (result.parsed_output_ref is not None) != expected_success
            or (
                expected_success
                and not _is_exact_output_artifact(
                    result.parsed_output_ref,
                    canonical_bytes(outcome.validated_output),
                    request,
                )
            )
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        return result

    async def cancel(self, invocation_id: str) -> CancellationResult:
        async with self._active_lock:
            task = self._active.get(invocation_id)
            cancel_event = self._cancel_events.get(invocation_id)
        if task is None:
            return CancellationResult(False, "No matching active invocation")
        if task is asyncio.current_task():
            return CancellationResult(False, "Invocation cannot cancel itself")
        if cancel_event is not None:
            cancel_event.set()
        task.cancel()
        result = await asyncio.shield(task)
        cancelled = result.status == "CANCELLED"
        return CancellationResult(
            cancelled,
            None if cancelled else "Invocation cancellation was not confirmed",
        )

    @staticmethod
    def _raise_if_cancel_requested(cancel_event: asyncio.Event) -> None:
        if cancel_event.is_set():
            raise asyncio.CancelledError


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail_unobservable_model_test(
    evidence: ProviderValidationEvidence,
) -> ProviderValidationEvidence:
    return evidence.model_copy(
        update={
            "tests": tuple(
                test.model_copy(
                    update={
                        "result": "FAIL",
                        "safe_summary": (
                            "Codex exec did not expose provider-reported model identity"
                        ),
                    }
                )
                if test.test_id == "PVD-02"
                else test
                for test in evidence.tests
            )
        }
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_execution_binding(binding: ApprovedCodexExecutionBinding) -> None:
    try:
        profile = ProviderProfile.model_validate(binding.provider_profile)
        client = ClientExecutionProfile.model_validate(binding.client_execution_profile)
        profile_ref = reference(profile)
        client_ref = reference(client)
        canonical_home = binding.codex_home.resolve(strict=True)
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("CODEX_EXECUTION_BINDING_MISMATCH") from error
    if (
        not isinstance(profile_ref, StoredDataRef)
        or not isinstance(client_ref, StoredDataRef)
        or profile.provider != "OPENAI"
        or profile.product != "CODEX"
        or profile.transport != "CODEX_CLIENT"
        or profile.auth_mode != "SUBSCRIPTION_LOGIN"
        or profile.credential_source != "OFFICIAL_CLIENT_SESSION"
        or profile.support_status != "EXPERIMENTAL"
        or profile.client_execution_profile_ref != client_ref
        or profile.validation_evidence_ref != client.verification_evidence_ref
        or profile.meta.analysis_id != client.meta.analysis_id
        or profile.meta.workspace_id != client.meta.workspace_id
        or profile.meta.commit_id != client.meta.commit_id
        or tuple(client.environment_variable_allowlist) != _CHILD_ENVIRONMENT_ALLOWLIST
        or binding.runtime_environment != profile.environment
        or not binding.codex_home.is_absolute()
        or binding.codex_home.is_symlink()
        or canonical_home != binding.codex_home
    ):
        raise ValueError("CODEX_EXECUTION_BINDING_MISMATCH")


def _require_codex_cli_version(result: _ChildResult, expected: str) -> None:
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        raise ProviderExecutableBindingError from None
    if result.returncode != 0 or lines != [f"codex-cli {expected}"]:
        raise ProviderExecutableBindingError


def _is_exact_chatgpt_login_status(result: _ChildResult) -> bool:
    try:
        lines = (result.stdout + result.stderr).decode("utf-8").splitlines()
    except UnicodeError:
        return False
    return result.returncode == 0 and lines == [_CHATGPT_LOGIN_STATUS]


def _validate_process_request(request: CodexProcessRequest) -> None:
    if (
        not request.invocation_id.strip()
        or not isinstance(request.provider_profile_ref, StoredDataRef)
        or not request.model.strip()
        or request.model.startswith("-")
        or any(
            not character.isascii() or not (character.isalnum() or character in "-._:/")
            for character in request.model
        )
        or request.timeout_ms <= 0
        or not request.prompt
        or not request.output_schema
    ):
        raise ProviderInputMismatchError


def _windows_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess)["CREATE_NEW_PROCESS_GROUP"]) | cast(
        int, vars(subprocess)["CREATE_NO_WINDOW"]
    )


def _windows_no_window_flag() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess)["CREATE_NO_WINDOW"])


async def _write_stdin(process: asyncio.subprocess.Process, data: bytes) -> None:
    writer = process.stdin
    if writer is None:
        raise RuntimeError("CODEX_STDIN_NOT_AVAILABLE")
    try:
        writer.write(data)
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _drain_bounded(reader: asyncio.StreamReader, retain_limit: int) -> bytes:
    retained = bytearray()
    while chunk := await reader.read(65_536):
        remaining = retain_limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained)


async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if os.name == "nt":
        tree_termination_confirmed = False
        windows_root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = Path(windows_root) / "System32" / "taskkill.exe"
        killer: asyncio.subprocess.Process | None = None
        try:
            killer = await asyncio.create_subprocess_exec(
                str(taskkill),
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=_windows_no_window_flag(),
            )
            tree_termination_confirmed = (
                await asyncio.wait_for(
                    asyncio.shield(killer.wait()),
                    timeout=_TREE_KILLER_TIMEOUT_SECONDS,
                )
                == 0
            )
        except (OSError, TimeoutError, asyncio.CancelledError):
            if killer is not None and killer.returncode is None:
                killer.kill()
                await asyncio.shield(killer.wait())
            tree_termination_confirmed = False
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await asyncio.shield(process.wait())
        if not tree_termination_confirmed:
            raise _ProcessTreeTerminationError
        return
    else:
        kill_group = cast(
            Callable[[int, int], None],
            vars(os)["killpg"],
        )
        terminate_signal = int(signal.SIGTERM)
        kill_signal = int(vars(signal)["SIGKILL"])
        tree_termination_confirmed = True
        try:
            kill_group(process.pid, terminate_signal)
        except ProcessLookupError:
            pass
        except PermissionError:
            tree_termination_confirmed = False
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=0.25)
        except TimeoutError:
            try:
                kill_group(process.pid, kill_signal)
            except ProcessLookupError:
                pass
            except PermissionError:
                tree_termination_confirmed = False
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    await asyncio.shield(process.wait())
    if not tree_termination_confirmed:
        raise _ProcessTreeTerminationError


def _classify_child_failure(
    result: _ChildResult,
) -> Literal["AUTH_REQUIRED", "RATE_LIMITED", "FAILED"]:
    diagnostic = (result.stdout + result.stderr).lower()
    if any(marker in diagnostic for marker in _RATE_LIMIT_MARKERS):
        return "RATE_LIMITED"
    if any(marker in diagnostic for marker in _AUTH_FAILURE_MARKERS):
        return "AUTH_REQUIRED"
    return "FAILED"


def _validated_session_id(event_stream: bytes) -> str:
    session_id: str | None = None
    state: Literal["THREAD", "TURN", "ITEMS", "DONE"] = "THREAD"
    if not event_stream or len(event_stream) >= _MAX_EVENT_STREAM_BYTES:
        raise ProviderInvalidOutputError
    for line in event_stream.splitlines():
        if not line.strip():
            continue
        event = _strict_json(line, ProviderInvalidOutputError)
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ProviderInvalidOutputError
        event_type = event["type"]
        if state == "THREAD" and event_type == "thread.started":
            observed = event.get("thread_id")
            if (
                session_id is not None
                or not isinstance(observed, str)
                or not observed.strip()
            ):
                raise ProviderInvalidOutputError
            session_id = observed
            state = "TURN"
        elif state == "TURN" and event_type == "turn.started":
            state = "ITEMS"
        elif state == "ITEMS" and event_type == "item.completed":
            item = event.get("item")
            if not isinstance(item, dict) or item.get("type") not in {
                "agent_message",
                "reasoning",
            }:
                raise ProviderInvalidOutputError
        elif state == "ITEMS" and event_type == "turn.completed":
            state = "DONE"
        else:
            raise ProviderInvalidOutputError
    if session_id is None or state != "DONE":
        raise ProviderInvalidOutputError
    return session_id


def _codex_output_schema(
    provider_neutral_schema: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    """Adapt only array roots to Codex's structured-output object transport."""
    if provider_neutral_schema.get("type") != "array":
        return provider_neutral_schema
    return cast(
        dict[str, JsonValue],
        {
            "type": "object",
            "properties": {_ARRAY_ENVELOPE_KEY: provider_neutral_schema},
            "required": [_ARRAY_ENVELOPE_KEY],
            "additionalProperties": False,
        },
    )


def _unwrap_codex_output(
    provider_output: JsonValue,
    provider_neutral_schema: dict[str, JsonValue],
) -> JsonValue:
    if provider_neutral_schema.get("type") != "array":
        return provider_output
    if (
        not isinstance(provider_output, dict)
        or set(provider_output) != {_ARRAY_ENVELOPE_KEY}
        or not isinstance(provider_output[_ARRAY_ENVELOPE_KEY], list)
    ):
        raise ProviderInvalidOutputError
    return provider_output[_ARRAY_ENVELOPE_KEY]


async def _cancel_and_wait(task: asyncio.Task[object]) -> BaseException | None:
    task.cancel()
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException as error:
            return error
    try:
        task.result()
    except asyncio.CancelledError:
        return None
    except BaseException as error:
        return error
    return None


def _strict_json(data: bytes, error_type: type[RuntimeError]) -> JsonValue:
    def reject_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        output: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON member")
            output[key] = value
        return output

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        return cast(
            JsonValue,
            json.loads(
                data.decode("utf-8"),
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            ),
        )
    except (UnicodeError, TypeError, ValueError) as error:
        raise error_type from error


def _is_exact_output_artifact(
    ref: StoredDataRef | None,
    data: bytes,
    request: LLMInvocationRequest,
) -> bool:
    if ref is None:
        return False
    digest = _sha256(data)
    return (
        ref.record_id is None
        and ref.data_kind == "artifact"
        and str(ref.stored_data_id) == digest
        and ref.content_hash == digest
        and ref.workspace_id == request.meta.workspace_id
        and ref.commit_id == request.meta.commit_id
    )


__all__ = [
    "ApprovedCodexExecutable",
    "ApprovedCodexExecutionBinding",
    "CodexCliProcessRunner",
    "CodexSubscriptionAdapter",
    "ProviderExecutableBindingError",
]
