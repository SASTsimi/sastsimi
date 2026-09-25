"""Both executable entry points use main(argv) -> int."""

import argparse
import asyncio
import re
import sys
from pathlib import Path
from typing import Any, NoReturn, cast
from uuid import uuid4

from sastsimi import bootstrap
from sastsimi.config.production_profile import load_production_profile
from sastsimi.config.user_config import UserConfigStore
from sastsimi.interfaces.cli import analyze as analyze_command
from sastsimi.interfaces.cli import cancel as cancel_command
from sastsimi.interfaces.cli import capability as capability_command
from sastsimi.interfaces.cli import codeql as codeql_command
from sastsimi.interfaces.cli import commands
from sastsimi.interfaces.cli import dashboard as dashboard_command
from sastsimi.interfaces.cli import local_evaluation as local_evaluation_command
from sastsimi.interfaces.cli import onboarding as onboarding_command
from sastsimi.interfaces.cli import public as public_command
from sastsimi.interfaces.cli import report as report_command
from sastsimi.interfaces.cli import reports as reports_command
from sastsimi.interfaces.cli import result as result_command
from sastsimi.interfaces.cli import setup as setup_command
from sastsimi.interfaces.cli import simple_evaluation as simple_evaluation_command
from sastsimi.interfaces.cli import status as status_command
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.output import emit_data, emit_result
from sastsimi.interfaces.cli.progress import ProgressRenderer
from sastsimi.orchestration.production_onboarding_builder import (
    ApprovedProbeResolver,
)
from sastsimi.runtime.system_support import SystemClock
from sastsimi.setup.service import SetupService


class _InputError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse includes raw user arguments in message; do not echo them.
        raise _InputError


def _configure_standard_streams() -> None:
    """Keep installed CLI output readable on Windows and redirected terminals."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict")


def _exact_commit(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
        raise argparse.ArgumentTypeError("exact commit required")
    return value


def _normalize_public_argv(argv: list[str] | None) -> list[str] | None:
    """Translate compact report syntax while preserving legacy subcommands."""

    if argv is None:
        return None
    normalized = list(argv)
    try:
        index = normalized.index("report")
    except ValueError:
        return normalized
    if index + 1 >= len(normalized) or normalized[index + 1] in {
        "show",
        "export",
        "-h",
        "--help",
    }:
        return normalized
    finding_id = normalized[index + 1]
    if normalized[index + 2 : index + 4] == ["--export", "markdown"]:
        return (
            normalized[: index + 1]
            + ["export", finding_id, "--format", "markdown"]
            + normalized[index + 4 :]
        )
    return normalized[: index + 1] + ["show", finding_id] + normalized[index + 2 :]


def _approved_probe_resolver(
    data_dir: Path,
    profile: Any,
    docker_host: str | None,
) -> ApprovedProbeResolver:
    """Resolve only already-approved, still-current probe revisions."""

    lookup = capability_command.build_service(
        data_dir,
        kind=None,
        host_id=profile.host_id,
        docker_host=None,
    )
    receipts = {item.probe_id: item for item in lookup.list()}

    def resolve(probe_id: str) -> tuple[str, Any]:
        receipt = receipts.get(probe_id)
        if (
            receipt is None
            or receipt.approved_profile_ref is None
            or receipt.approval_target_hash is None
        ):
            raise ValueError("CAPABILITY_PROBE_NOT_APPROVED")
        service = capability_command.build_service(
            data_dir,
            kind=receipt.kind,
            host_id=profile.host_id,
            docker_host=docker_host,
            codeql_container_config=profile.codeql_container,
        )
        current = service.require_approved_current(
            receipt.probe_id,
            receipt.approved_profile_ref,
        )
        if current != receipt.approved_profile_ref:
            raise ValueError("CAPABILITY_APPROVED_REFERENCE_CHANGED")
        return str(receipt.kind), current

    return resolve


def main(
    argv: list[str] | None = None,
    *,
    production_analyze: analyze_command.ProductionAnalyzeEntrypoint | None = None,
    production_query: analyze_command.ProductionQueryEntrypoint | None = None,
    local_evaluation_analyze: (
        local_evaluation_command.LocalEvaluationAnalyzeEntrypoint | None
    ) = None,
    setup_service: SetupService | None = None,
    public_application: public_command.PublicCommandApplication | None = None,
    user_config_store: UserConfigStore | None = None,
) -> int:
    _configure_standard_streams()
    output_format = "text"
    command_name = "doctor"
    parser = _Parser(prog="sastsimi", allow_abbrev=False)
    parser.add_argument("--config", type=Path, help="explicit approved versioned TOML")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    )
    parser.add_argument(
        "--data-dir", type=Path, help="local runtime root (not created by doctor)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    setup_parser = subparsers.add_parser(
        "setup", help="configure local analysis defaults", allow_abbrev=False
    )
    setup_parser.add_argument("--non-interactive", action="store_true")
    setup_parser.add_argument("--data-dir", dest="setup_data_dir", type=Path)
    setup_parser.add_argument("--auth", choices=["api-key", "subscription"])
    setup_parser.add_argument("--provider")
    setup_parser.add_argument("--model")
    setup_parser.add_argument("--agent-model", action="append", default=[])
    setup_parser.add_argument("--llm-timeout-seconds", type=int, default=180)
    setup_parser.add_argument("--llm-max-retries", type=int, default=2)
    setup_parser.add_argument("--llm-max-concurrency", type=int, default=2)
    setup_parser.add_argument(
        "--hypothesis-feed", choices=["current", "facts_survey"], default="current"
    )
    setup_parser.add_argument("--max-parallel-hypotheses", type=int, default=1)
    setup_parser.add_argument("--max-parallel-builds", type=int, default=1)
    setup_parser.add_argument("--max-parallel-containers", type=int, default=1)
    setup_parser.add_argument("--cursor-allow-on-demand", action="store_true")
    setup_parser.add_argument(
        "--fallback-provider", choices=["none", "openai", "codex"], default="none"
    )
    setup_parser.add_argument("--fallback-model")
    setup_parser.add_argument(
        "--profile", dest="execution_profile", choices=["full", "lightweight"]
    )
    setup_parser.add_argument(
        "--docker-network", choices=["none", "bridge"], default="none"
    )
    setup_parser.add_argument("--max-cost-minor-units", type=int, default=100_000)
    setup_parser.add_argument("--max-tokens", type=int, default=1_000_000)
    setup_parser.add_argument("--max-elapsed-seconds", type=int, default=3_600)
    setup_parser.add_argument("--format", choices=["text", "json"])
    subparsers.add_parser(
        "cursor-models",
        help="list model IDs from the Cursor CLI login or CURSOR_API_KEY",
        allow_abbrev=False,
    )
    doctor_parser = subparsers.add_parser(
        "doctor", help="read-only foundation host checks", allow_abbrev=False
    )
    doctor_parser.add_argument("--format", choices=["text", "json"])
    db_parser = subparsers.add_parser(
        "db", help="explicit database maintenance", allow_abbrev=False
    )
    db_commands = db_parser.add_subparsers(dest="db_command", required=True)
    upgrade_parser = db_commands.add_parser("upgrade", allow_abbrev=False)
    upgrade_parser.add_argument("revision", nargs="?", default="head")
    upgrade_parser.add_argument("--format", choices=["text", "json"])
    current_parser = db_commands.add_parser("current", allow_abbrev=False)
    current_parser.add_argument("--format", choices=["text", "json"])
    downgrade_parser = db_commands.add_parser("downgrade", allow_abbrev=False)
    downgrade_parser.add_argument("revision")
    downgrade_parser.add_argument("--format", choices=["text", "json"])
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="serve a local read-only analysis dashboard",
        allow_abbrev=False,
    )
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8765)
    analyze_parser = subparsers.add_parser(
        "analyze", help="run a production repository analysis", allow_abbrev=False
    )
    analyze_parser.add_argument("repository", nargs="?")
    analyze_parser.add_argument("--repo", dest="repository_option")
    analyze_parser.add_argument("--commit", required=True, type=_exact_commit)
    analyze_parser.add_argument("--profile", type=Path)
    analyze_parser.add_argument("--no-progress", action="store_true")
    analyze_parser.add_argument("--format", choices=["text", "json"])
    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="run explicitly non-production local evaluation",
        allow_abbrev=False,
    )
    evaluate_commands = evaluate_parser.add_subparsers(
        dest="evaluate_command", required=True
    )
    evaluate_analyze = evaluate_commands.add_parser("analyze", allow_abbrev=False)
    evaluate_analyze.add_argument("--repo", required=True)
    evaluate_analyze.add_argument("--commit", required=True, type=_exact_commit)
    evaluate_analyze.add_argument("--profile", required=True, type=Path)
    evaluate_analyze.add_argument("--format", choices=["text", "json"])
    evaluate_resume = evaluate_commands.add_parser("resume", allow_abbrev=False)
    evaluate_resume.add_argument("analysis_id")
    evaluate_resume.add_argument("--profile", required=True, type=Path)
    evaluate_resume.add_argument("--format", choices=["text", "json"])
    evaluate_simple_resume = evaluate_commands.add_parser(
        "simple-resume", allow_abbrev=False
    )
    evaluate_simple_resume.add_argument("analysis_id")
    evaluate_simple_resume.add_argument("--hypothesis-id")
    evaluate_simple_resume.add_argument("--profile", required=True, type=Path)
    evaluate_simple_resume.add_argument("--format", choices=["text", "json"])
    status_parser = subparsers.add_parser(
        "status", help="read production analysis progress", allow_abbrev=False
    )
    status_parser.add_argument("analysis_id")
    status_parser.add_argument("--format", choices=["text", "json"])
    cancel_parser = subparsers.add_parser(
        "cancel", help="durably request analysis cancellation", allow_abbrev=False
    )
    cancel_parser.add_argument("analysis_id")
    cancel_parser.add_argument("--format", choices=["text", "json"])
    resume_parser = subparsers.add_parser(
        "resume",
        help="validate pinned restart input (dispatch unavailable)",
        allow_abbrev=False,
    )
    resume_parser.add_argument("analysis_id")
    resume_parser.add_argument("--no-progress", action="store_true")
    resume_parser.add_argument("--format", choices=["text", "json"])
    results_parser = subparsers.add_parser(
        "results", help="read one terminal production result", allow_abbrev=False
    )
    results_parser.add_argument("analysis_id")
    results_parser.add_argument("--format", choices=["text", "json"])
    result_parser = subparsers.add_parser(
        "result", help="show one SimpleRuntime result", allow_abbrev=False
    )
    result_parser.add_argument("analysis_id")
    result_parser.add_argument("--format", choices=["text", "json"])
    poc_parser = subparsers.add_parser(
        "poc", help="show one validated PoC", allow_abbrev=False
    )
    poc_parser.add_argument("finding_id")
    poc_parser.add_argument("--format", choices=["text", "json"])
    reports_parser = subparsers.add_parser(
        "reports", help="list current human-review reports", allow_abbrev=False
    )
    reports_parser.add_argument("analysis_id")
    reports_parser.add_argument("--format", choices=["text", "json"])
    report_parser = subparsers.add_parser(
        "report", help="show or export one current report", allow_abbrev=False
    )
    report_commands = report_parser.add_subparsers(dest="report_command", required=True)
    report_show = report_commands.add_parser("show", allow_abbrev=False)
    report_show.add_argument("finding_id")
    report_export = report_commands.add_parser("export", allow_abbrev=False)
    report_export.add_argument("finding_id")
    report_export.add_argument(
        "--format", dest="export_format", choices=["markdown"], required=True
    )
    onboarding_parser = subparsers.add_parser(
        "onboarding",
        help="record and verify production provider/prompt approvals",
        allow_abbrev=False,
    )
    onboarding_commands = onboarding_parser.add_subparsers(
        dest="onboarding_command", required=True
    )
    onboarding_init = onboarding_commands.add_parser(
        "init",
        help="write a pending probe and approval plan without granting approval",
        allow_abbrev=False,
    )
    onboarding_init.add_argument("--profile", type=Path, required=True)
    onboarding_init.add_argument("--output-dir", type=Path, required=True)
    onboarding_init.add_argument("--format", choices=["text", "json"])
    onboarding_requirements = onboarding_commands.add_parser(
        "requirements", allow_abbrev=False
    )
    onboarding_requirements.add_argument("--profile", type=Path, required=True)
    onboarding_requirements.add_argument("--format", choices=["text", "json"])
    onboarding_compose = onboarding_commands.add_parser("compose", allow_abbrev=False)
    onboarding_compose.add_argument("--profile", type=Path, required=True)
    onboarding_compose.add_argument("--approval-input", type=Path, required=True)
    onboarding_compose.add_argument(
        "--slot-template", type=Path, action="append", required=True
    )
    onboarding_compose.add_argument(
        "--evidence", type=Path, action="append", default=[]
    )
    onboarding_compose.add_argument("--output-dir", type=Path, required=True)
    onboarding_compose.add_argument("--docker-host")
    onboarding_compose.add_argument("--format", choices=["text", "json"])
    onboarding_prepare = onboarding_commands.add_parser("prepare", allow_abbrev=False)
    onboarding_prepare.add_argument("--profile", type=Path, required=True)
    onboarding_prepare_input = onboarding_prepare.add_mutually_exclusive_group(
        required=True
    )
    onboarding_prepare_input.add_argument("--manifest", type=Path)
    onboarding_prepare_input.add_argument("--bundle-dir", type=Path)
    onboarding_prepare.add_argument(
        "--evidence", type=Path, action="append", default=[]
    )
    onboarding_prepare.add_argument("--format", choices=["text", "json"])
    onboarding_status = onboarding_commands.add_parser("status", allow_abbrev=False)
    onboarding_status.add_argument("--profile", type=Path, required=True)
    onboarding_status.add_argument("--format", choices=["text", "json"])
    capability_parser = subparsers.add_parser(
        "capability",
        help="probe and approve production capabilities",
        allow_abbrev=False,
    )
    capability_parser.add_argument("--host-id")
    capability_commands = capability_parser.add_subparsers(
        dest="capability_command", required=True
    )
    capability_probe = capability_commands.add_parser("probe", allow_abbrev=False)
    capability_probe.add_argument(
        "kind",
        choices=[
            "GIT",
            "PYTHON_AST",
            "PYTHON_RUNTIME",
            "OPENGREP",
            "DOCKER",
            "OPENAI_API",
            "CODEQL",
        ],
    )
    capability_probe.add_argument("--model")
    capability_probe.add_argument("--credential-ref")
    capability_probe.add_argument("--docker-host")
    capability_probe.add_argument("--profile", type=Path)
    capability_probe.add_argument("--format", choices=["text", "json"])
    capability_list = capability_commands.add_parser("list", allow_abbrev=False)
    capability_list.add_argument("--format", choices=["text", "json"])
    capability_approve = capability_commands.add_parser("approve", allow_abbrev=False)
    capability_approve.add_argument("probe_id")
    capability_approve.add_argument("--target-hash", required=True)
    capability_approve.add_argument("--docker-host")
    capability_approve.add_argument("--profile", type=Path)
    capability_approve.add_argument("--format", choices=["text", "json"])
    codeql_parser = subparsers.add_parser(
        "codeql",
        help="provision, register, or inspect controlled CodeQL databases",
        allow_abbrev=False,
    )
    codeql_commands = codeql_parser.add_subparsers(dest="codeql_command", required=True)
    codeql_register = codeql_commands.add_parser("register", allow_abbrev=False)
    codeql_inspect = codeql_commands.add_parser("inspect", allow_abbrev=False)
    codeql_provision = codeql_commands.add_parser("provision", allow_abbrev=False)
    for codeql_action in (codeql_register, codeql_inspect):
        codeql_action.add_argument("--profile", type=Path, required=True)
        codeql_action.add_argument("--repo", required=True)
        codeql_action.add_argument("--commit", type=_exact_commit, required=True)
        codeql_action.add_argument(
            "--language",
            choices=["python", "javascript-typescript"],
            required=True,
        )
        codeql_action.add_argument("--tracked-manifest-sha256", required=True)
        codeql_action.add_argument("--format", choices=["text", "json"])
    codeql_register.add_argument("--database-root", type=Path, required=True)
    codeql_provision.add_argument("--profile", type=Path, required=True)
    codeql_provision.add_argument("--repo", required=True)
    codeql_provision.add_argument("--commit", type=_exact_commit, required=True)
    codeql_provision.add_argument("--language", choices=["python"], required=True)
    codeql_provision.add_argument("--repository-root", type=Path, required=True)
    codeql_provision.add_argument("--format", choices=["text", "json"])
    try:
        raw_argv = list(sys.argv[1:]) if argv is None else argv
        args = parser.parse_args(_normalize_public_argv(raw_argv))
        requested_output = getattr(args, "format", None)
        if requested_output is not None:
            output_format = requested_output
        selected_user_store = user_config_store or UserConfigStore()
        user_config = None
        if args.command not in {"setup", "cursor-models"}:
            try:
                user_config = selected_user_store.load()
            except ValueError:
                user_config = None
        overrides = {
            key: value
            for key, value in {
                "log_level": args.log_level,
                "data_dir": args.data_dir
                or (user_config.data_dir if user_config is not None else None),
                "output_format": requested_output,
            }.items()
            if value is not None
        }
        config = bootstrap.build_config(args.config, overrides)
        output_format = config.output_format

        def resolve_public_application() -> public_command.PublicCommandApplication:
            nonlocal public_application
            if public_application is None:
                from sastsimi.composition.simple_runtime_composition import (
                    build_public_simple_runtime,
                )

                public_application = build_public_simple_runtime(selected_user_store)
            return public_application

        if args.command == "cursor-models":
            from sastsimi.composition.simple_runtime_composition import (
                list_cursor_models,
            )

            try:
                models = asyncio.run(list_cursor_models())
            except ValueError as error:
                cursor_setup_code = (
                    "CURSOR_CLI_NOT_INSTALLED"
                    if str(error) == "CURSOR_CLI_NOT_INSTALLED"
                    else "CURSOR_AUTH_REQUIRED"
                )
                sys.stderr.write(
                    cursor_setup_code + ": install or log in to Cursor CLI\n"
                )
                return int(ExitCode.CONFIG_ERROR)
            except Exception as error:
                name = type(error).__name__
                cursor_error_code = (
                    "CURSOR_AUTH_FAILED"
                    if name in {"AuthenticationError", "CursorCLIAuthenticationError"}
                    else "CURSOR_MODEL_CATALOG_FAILED"
                )
                sys.stderr.write(
                    cursor_error_code
                    + ": check Cursor CLI login or API key and connectivity\n"
                )
                return int(ExitCode.BLOCKED)
            for model_id in sorted(models):
                sys.stdout.write(model_id + "\n")
            return int(ExitCode.OK)

        if args.command == "setup":
            command_name = "setup"
            service = setup_service or SetupService()
            setup_result = setup_command.run(service, args)
            setup_code = (
                ExitCode.OK
                if setup_result.status == "READY"
                else ExitCode.CAPABILITY_UNSUPPORTED
            )
            if output_format != "json":
                target = sys.stdout if setup_code == ExitCode.OK else sys.stderr
                headline = (
                    "설정이 완료되었습니다.\n"
                    if setup_code == ExitCode.OK
                    else "설정에 필요한 항목이 남았습니다.\n"
                )
                target.write(
                    headline
                    + f"기본 설정: {setup_result.config_path}\n"
                    + f"실행 프로필: {setup_result.profile_path}\n"
                )
                if setup_result.missing_tools:
                    target.write(
                        "설치 또는 확인 필요: "
                        + ", ".join(setup_result.missing_tools)
                        + "\n"
                    )
                for action in setup_result.next_actions:
                    target.write(f"- {action}\n")
                return int(setup_code)
            emit_data(
                output_format,
                sys.stdout if setup_code == ExitCode.OK else sys.stderr,
                command=command_name,
                code=setup_code,
                data={
                    "status": setup_result.status,
                    "config_path": str(setup_result.config_path),
                    "profile_path": str(setup_result.profile_path),
                    "missing_tools": list(setup_result.missing_tools),
                    "next_actions": list(setup_result.next_actions),
                },
            )
            return int(setup_code)
        if args.command == "db":
            command_name = "db " + args.db_command
            revision = bootstrap.database_command(
                config.data_dir, args.db_command, getattr(args, "revision", None)
            )
            emit_result(
                ExitCode.OK,
                output_format,
                sys.stdout,
                command=command_name,
                revision=revision,
            )
            return int(ExitCode.OK)
        if args.command == "dashboard":
            command_name = "dashboard"
            dashboard_command.run(config.data_dir, args.host, args.port)
            return int(ExitCode.OK)
        if args.command == "analyze":
            command_name = "analyze"
            repository = args.repository or args.repository_option
            if repository is None or (
                args.repository is not None and args.repository_option is not None
            ):
                raise _InputError
            if args.profile is None:
                application = resolve_public_application()
                progress_call = getattr(application, "analyze_with_progress", None)
                if (
                    output_format != "json"
                    and not args.no_progress
                    and callable(progress_call)
                ):
                    renderer = ProgressRenderer(
                        stream=sys.stdout,
                        is_tty=sys.stdout.isatty(),
                    )
                    data = progress_call(repository, args.commit, renderer.render)
                else:
                    data = application.analyze(repository, args.commit)
                public_command.emit_public(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data=data,
                )
                return int(ExitCode.OK)
            if production_analyze is None:
                production_analyze = cast(
                    analyze_command.ProductionAnalyzeEntrypoint,
                    bootstrap.build_production_analyze(),
                )
            request = analyze_command.ProductionAnalyzeRequest(
                data_dir=config.data_dir,
                repository=repository,
                commit=args.commit,
                profile=args.profile,
            )
            analyze_result = asyncio.run(
                analyze_command.run(production_analyze, request)
            )
            emit_data(
                output_format,
                sys.stdout if analyze_result.code == ExitCode.OK else sys.stderr,
                command=command_name,
                data=analyze_result.data,
                code=analyze_result.code,
            )
            return int(analyze_result.code)
        if args.command == "evaluate":
            command_name = "evaluate " + args.evaluate_command
            if args.evaluate_command == "simple-resume":
                simple_data = asyncio.run(
                    simple_evaluation_command.resume(
                        data_dir=config.data_dir,
                        analysis_id=args.analysis_id,
                        profile_path=args.profile,
                        hypothesis_id=args.hypothesis_id,
                    )
                )
                simple_status = simple_data["status"]
                simple_code = (
                    ExitCode.RUN_FAILED
                    if simple_status == "FAILED"
                    else ExitCode.BLOCKED
                    if simple_status == "BLOCKED"
                    else ExitCode.OK
                )
                emit_data(
                    output_format,
                    sys.stdout if simple_code == ExitCode.OK else sys.stderr,
                    command=command_name,
                    data=simple_data,
                    code=simple_code,
                )
                return int(simple_code)
            if local_evaluation_analyze is None:
                local_evaluation_analyze = cast(
                    local_evaluation_command.LocalEvaluationAnalyzeEntrypoint,
                    bootstrap.build_local_evaluation_analyze(),
                )
            if args.evaluate_command == "analyze":
                analyze_request = (
                    local_evaluation_command.LocalEvaluationAnalyzeRequest(
                        data_dir=config.data_dir,
                        repository=args.repo,
                        commit=args.commit,
                        profile=args.profile,
                    )
                )
                evaluation_result = asyncio.run(
                    local_evaluation_command.run(
                        local_evaluation_analyze, analyze_request
                    )
                )
            else:
                resume_request = local_evaluation_command.LocalEvaluationResumeRequest(
                    data_dir=config.data_dir,
                    analysis_id=args.analysis_id,
                    profile=args.profile,
                )
                evaluation_result = asyncio.run(
                    local_evaluation_command.resume(
                        local_evaluation_analyze, resume_request
                    )
                )
            emit_data(
                output_format,
                sys.stdout if evaluation_result.code == ExitCode.OK else sys.stderr,
                command=command_name,
                data=evaluation_result.data,
                code=evaluation_result.code,
            )
            return int(evaluation_result.code)
        if args.command == "resume":
            command_name = "resume"
            if public_application is not None or args.analysis_id.startswith("A-"):
                application = resolve_public_application()
                progress_call = getattr(application, "resume_with_progress", None)
                if (
                    output_format != "json"
                    and not args.no_progress
                    and callable(progress_call)
                ):
                    renderer = ProgressRenderer(
                        stream=sys.stdout,
                        is_tty=sys.stdout.isatty(),
                    )
                    data = progress_call(args.analysis_id, renderer.render)
                else:
                    data = application.resume(args.analysis_id)
                public_command.emit_public(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data=data,
                )
                return int(ExitCode.OK)
            bootstrap.inspect_production_resume(config.data_dir, args.analysis_id)
        if args.command == "cancel":
            command_name = "cancel"
            try:
                view = bootstrap.request_production_cancel(
                    config.data_dir, args.analysis_id
                )
            except ValueError:
                emit_result(
                    ExitCode.INTEGRITY_ERROR,
                    output_format,
                    sys.stderr,
                    command=command_name,
                )
                return int(ExitCode.INTEGRITY_ERROR)
            emit_data(
                output_format,
                sys.stdout,
                command=command_name,
                data=cancel_command.project(view),
            )
            return int(ExitCode.OK)
        if args.command == "status":
            command_name = "status"
            if public_application is not None or args.analysis_id.startswith("A-"):
                application = resolve_public_application()
                data = application.status(args.analysis_id)
                public_command.emit_public(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data=data,
                )
                return int(ExitCode.OK)
            if production_query is None:
                production_query = cast(
                    analyze_command.ProductionQueryEntrypoint,
                    bootstrap.build_production_query(config.data_dir),
                )
            data = status_command.run(production_query, args.analysis_id)
            emit_data(output_format, sys.stdout, command=command_name, data=data)
            return int(ExitCode.OK)
        if args.command == "results":
            command_name = "results"
            if production_query is None:
                production_query = cast(
                    analyze_command.ProductionQueryEntrypoint,
                    bootstrap.build_production_query(config.data_dir),
                )
            data = result_command.run(
                production_query,
                args.analysis_id,
                output_format="json" if output_format == "json" else "summary",
            )
            emit_data(output_format, sys.stdout, command=command_name, data=data)
            return int(ExitCode.OK)
        if args.command == "result":
            command_name = "result"
            application = resolve_public_application()
            data = application.result(args.analysis_id)
            public_command.emit_public(
                output_format,
                sys.stdout,
                command=command_name,
                data=data,
            )
            return int(ExitCode.OK)
        if args.command == "poc":
            command_name = "poc"
            application = resolve_public_application()
            value = application.poc(args.finding_id)
            if output_format == "json":
                emit_data(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data={"finding_id": args.finding_id, "content": value},
                )
            else:
                sys.stdout.write(value)
            return int(ExitCode.OK)
        if args.command == "reports":
            command_name = "reports"
            data = reports_command.run(config.data_dir, args.analysis_id)
            emit_data(output_format, sys.stdout, command=command_name, data=data)
            return int(ExitCode.OK)
        if args.command == "report":
            command_name = "report " + args.report_command
            report_application = public_application
            if report_application is None and args.finding_id.startswith("F-"):
                try:
                    report_application = resolve_public_application()
                except (FileNotFoundError, ValueError):
                    report_application = None
            show_public = getattr(report_application, "report", None)
            export_public = getattr(report_application, "export_report", None)
            if args.report_command == "show" and callable(show_public):
                sys.stdout.write(show_public(args.finding_id))
            elif args.report_command == "export" and callable(export_public):
                emit_data(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data={
                        "finding_id": args.finding_id,
                        "path": export_public(args.finding_id),
                    },
                )
            elif args.report_command == "show":
                sys.stdout.write(report_command.show(config.data_dir, args.finding_id))
            else:
                path = report_command.export(config.data_dir, args.finding_id)
                emit_data(
                    output_format,
                    sys.stdout,
                    command=command_name,
                    data={
                        "finding_id": args.finding_id,
                        "path": report_command.safe_export_reference(
                            config.data_dir, path
                        ),
                    },
                )
            return int(ExitCode.OK)
        if args.command == "onboarding":
            command_name = "onboarding " + args.onboarding_command
            profile = load_production_profile(args.profile)
            repository_root = bootstrap.builtin_resource_root()
            if args.onboarding_command == "init":
                onboarding_result = onboarding_command.run_init(
                    args.output_dir,
                    profile=profile,
                    repository_root=repository_root,
                )
            elif args.onboarding_command == "requirements":
                onboarding_result = onboarding_command.run_requirements(
                    profile, repository_root=repository_root
                )
            elif args.onboarding_command == "compose":
                onboarding_result = onboarding_command.run_compose(
                    config.data_dir,
                    profile=profile,
                    approval_input_path=args.approval_input,
                    slot_template_paths=tuple(args.slot_template),
                    evidence_paths=tuple(args.evidence),
                    output_dir=args.output_dir,
                    repository_root=repository_root,
                    clock=SystemClock().now,
                    resolve_probe=_approved_probe_resolver(
                        config.data_dir, profile, args.docker_host
                    ),
                )
            elif args.onboarding_command == "prepare":
                if args.bundle_dir is not None:
                    if args.evidence:
                        raise _InputError
                    onboarding_result = onboarding_command.run_prepare_bundle(
                        config.data_dir,
                        profile=profile,
                        bundle_dir=args.bundle_dir,
                        repository_root=repository_root,
                        clock=SystemClock().now,
                    )
                else:
                    onboarding_result = onboarding_command.run_prepare(
                        config.data_dir,
                        profile=profile,
                        manifest_path=args.manifest,
                        evidence_paths=tuple(args.evidence),
                        repository_root=repository_root,
                        clock=SystemClock().now,
                    )
            else:
                onboarding_result = onboarding_command.run_status(
                    config.data_dir,
                    profile=profile,
                    repository_root=repository_root,
                    clock=SystemClock().now,
                )
            emit_data(
                output_format,
                sys.stdout,
                command=command_name,
                data=onboarding_result.data,
            )
            return int(onboarding_result.code)
        if args.command == "capability":
            command_name = "capability " + args.capability_command
            codeql_config = None
            profile_path = getattr(args, "profile", None)
            if args.capability_command == "probe" and args.kind == "CODEQL":
                if profile_path is None:
                    raise _InputError
                codeql_config = load_production_profile(profile_path).codeql_container
                if codeql_config is None:
                    raise bootstrap.ProductionProfileError("CODEQL_CONTAINER_REQUIRED")
            elif profile_path is not None:
                codeql_config = load_production_profile(profile_path).codeql_container
            if args.capability_command == "probe":
                outcome = capability_command.run_probe(
                    config.data_dir,
                    kind=args.kind,
                    model=args.model,
                    credential_ref=args.credential_ref,
                    host_id=args.host_id,
                    docker_host=args.docker_host,
                    codeql_container_config=codeql_config,
                )
            elif args.capability_command == "list":
                outcome = capability_command.run_list(
                    config.data_dir,
                    host_id=args.host_id,
                )
            else:
                outcome = capability_command.run_approve(
                    config.data_dir,
                    probe_id=args.probe_id,
                    target_hash=args.target_hash,
                    host_id=args.host_id,
                    docker_host=args.docker_host,
                    codeql_container_config=codeql_config,
                )
            emit_data(
                output_format,
                sys.stdout if outcome.code == ExitCode.OK else sys.stderr,
                command=command_name,
                data=outcome.data,
                code=outcome.code,
            )
            return int(outcome.code)
        if args.command == "codeql":
            command_name = "codeql " + args.codeql_command
            profile = load_production_profile(args.profile)
            codeql_config = profile.codeql_container
            if codeql_config is None:
                emit_result(
                    ExitCode.CONFIG_ERROR,
                    output_format,
                    sys.stderr,
                    command=command_name,
                )
                return int(ExitCode.CONFIG_ERROR)
            if args.codeql_command == "register":
                outcome = codeql_command.run_register(
                    config=codeql_config,
                    repository_url=args.repo,
                    commit_id=args.commit,
                    language=args.language,
                    tracked_manifest_sha256=args.tracked_manifest_sha256,
                    database_root=args.database_root,
                )
            elif args.codeql_command == "provision":
                outcome = codeql_command.run_provision(
                    config=codeql_config,
                    repository_url=args.repo,
                    commit_id=args.commit,
                    language=args.language,
                    repository_root=args.repository_root,
                    git_executable=codeql_command.resolve_operator_executable(
                        profile.tools.git
                    ),
                    docker_executable=codeql_command.resolve_operator_executable(
                        profile.tools.docker
                    ),
                )
            else:
                outcome = codeql_command.run_inspect(
                    config=codeql_config,
                    repository_url=args.repo,
                    commit_id=args.commit,
                    language=args.language,
                    tracked_manifest_sha256=args.tracked_manifest_sha256,
                )
            emit_data(
                output_format,
                sys.stdout if outcome.code == ExitCode.OK else sys.stderr,
                command=command_name,
                data=outcome.data,
                code=outcome.code,
            )
            return int(outcome.code)
        else:
            code = ExitCode.OK if commands.doctor() else ExitCode.CAPABILITY_UNSUPPORTED
        emit_result(
            code, output_format, sys.stdout if code == ExitCode.OK else sys.stderr
        )
        return int(code)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.INPUT_ERROR)
    except _InputError:
        code = ExitCode.INPUT_ERROR
    except bootstrap.ConfigError:
        code = ExitCode.CONFIG_ERROR
    except bootstrap.ProductionProfileError:
        code = ExitCode.CONFIG_ERROR
    except bootstrap.MigrationRequired:
        code = ExitCode.CONFIG_ERROR
    except (
        analyze_command.ProductionAnalyzeUnavailable,
        local_evaluation_command.LocalEvaluationUnavailable,
        bootstrap.ProductionResumeUnavailable,
    ) as error:
        emit_result(
            ExitCode.CAPABILITY_UNSUPPORTED,
            output_format,
            sys.stderr,
            command=command_name,
            reason_code=error.reason_code,
        )
        return int(ExitCode.CAPABILITY_UNSUPPORTED)
    except report_command.ReportCommandError:
        code = ExitCode.REPORT_UNAVAILABLE
    except result_command.ResultIncomplete:
        code = ExitCode.RESULT_INCOMPLETE
    except result_command.ResultIntegrityError:
        code = ExitCode.INTEGRITY_ERROR
    except public_command.PublicCommandUnavailable:
        code = ExitCode.CONFIG_ERROR
    except Exception:
        trace_id = "trace-" + str(uuid4())
        logger = bootstrap.build_diagnostic_logger(sys.stderr, "ERROR")
        logger.error(
            bootstrap.diagnostic_event("internal_error", {}, trace_id=trace_id)
        )
        emit_result(
            ExitCode.INTERNAL_ERROR, output_format, sys.stderr, trace_id=trace_id
        )
        return int(ExitCode.INTERNAL_ERROR)
    emit_result(code, output_format, sys.stderr, command=command_name)
    return int(code)
