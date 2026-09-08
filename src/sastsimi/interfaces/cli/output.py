"""Deterministic public CLI envelope; only controlled diagnostic content."""

import json
from typing import TextIO

from sastsimi.interfaces.cli.exit_codes import ExitCode


def emit_result(
    code: ExitCode,
    output_format: str,
    stream: TextIO,
    *,
    trace_id: str | None = None,
    command: str = "doctor",
    revision: str | None = None,
) -> None:
    messages = {
        ExitCode.OK: (
            "Foundation host checks passed; external capabilities are not assessed."
        ),
        ExitCode.INPUT_ERROR: "Invalid command or option; use --help.",
        ExitCode.CONFIG_ERROR: (
            "Invalid configuration; check the approved file and allowed overrides."
        ),
        ExitCode.CAPABILITY_UNSUPPORTED: (
            "CAPABILITY_UNSUPPORTED: use 64-bit CPython 3.12 on Windows 11, "
            "Windows Server 2022 or Ubuntu 24.04 x86-64."
        ),
        ExitCode.INTERNAL_ERROR: (
            "Unexpected internal error; retain the diagnostic trace ID."
        ),
    }
    data: dict[str, object] = {"message": messages[code]}
    if command.startswith("db "):
        data["message"] = (
            "Database command completed."
            if code == ExitCode.OK
            else "Database migration unavailable; verify the revision and backup."
        )
        data["revision"] = revision
    if trace_id is not None:
        data["trace_id"] = trace_id
    if output_format == "json":
        envelope = {
            "schema_version": 1,
            "command": command,
            "status": "ok" if code == ExitCode.OK else "error",
            "code": code.name,
            "data": data,
        }
        stream.write(json.dumps(envelope, sort_keys=True) + "\n")
    else:
        stream.write(
            str(data["message"])
            + (f" Revision: {revision}" if revision else "")
            + (f" Trace: {trace_id}" if trace_id else "")
            + "\n"
        )
