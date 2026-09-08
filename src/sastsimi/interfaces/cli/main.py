"""Both executable entry points use main(argv) -> int."""

import argparse
import sys
from pathlib import Path
from typing import NoReturn
from uuid import uuid4

from sastsimi import bootstrap
from sastsimi.interfaces.cli import commands
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.output import emit_result


class _InputError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse includes raw user arguments in message; do not echo them.
        raise _InputError


def main(argv: list[str] | None = None) -> int:
    output_format = "text"
    parser = _Parser(prog="sastsimi", allow_abbrev=False)
    parser.add_argument("--config", type=Path, help="explicit approved versioned TOML")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    )
    parser.add_argument(
        "--data-dir", type=Path, help="local runtime root (not created by doctor)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor_parser = subparsers.add_parser(
        "doctor", help="read-only foundation host checks", allow_abbrev=False
    )
    doctor_parser.add_argument("--format", choices=["text", "json"])
    db_parser = subparsers.add_parser(
        "db", help="explicit database maintenance", allow_abbrev=False
    )
    db_commands = db_parser.add_subparsers(dest="db_command", required=True)
    upgrade_parser = db_commands.add_parser("upgrade", allow_abbrev=False)
    upgrade_parser.add_argument("--format", choices=["text", "json"])
    try:
        args = parser.parse_args(argv)
        if args.format is not None:
            output_format = args.format
        overrides = {
            key: value
            for key, value in {
                "log_level": args.log_level,
                "data_dir": args.data_dir,
                "output_format": args.format,
            }.items()
            if value is not None
        }
        config = bootstrap.build_config(args.config, overrides)
        output_format = config.output_format
        if args.command == "db":
            bootstrap.upgrade_database(config.data_dir)
            code = ExitCode.OK
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
    emit_result(code, output_format, sys.stderr)
    return int(code)
