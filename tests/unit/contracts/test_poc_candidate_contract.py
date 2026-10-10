"""Narrow placeholder guard regressions for shell PoC candidates."""

from __future__ import annotations

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.poc_candidate import (
    PoCCandidateRejected,
    candidate_rejection_diagnostic,
    validate_candidate,
)
from sastsimi.contracts.prompt_redaction import inspect_poc_candidate_json


def test_rejection_diagnostic_contains_only_closed_reason_and_counts() -> None:
    script = (
        b"#!/bin/sh\nif true; then\n"
        b"  printf 'SASTSIMI_POC_INCONCLUSIVE-HIDDEN_SENTINEL\\n'\n"
        b"  exit 2\nfi\n"
    )

    diagnostic = candidate_rejection_diagnostic(script, "POC_PLACEHOLDER_FORBIDDEN")

    assert diagnostic == {
        "reason": "INCONCLUSIVE_EXIT2_UNPROVEN",
        "line_count": 5,
        "branch_count": 1,
        "inconclusive_line_count": 1,
        "exit_two_line_count": 1,
        "exit_zero_line_count": 0,
    }
    assert b"HIDDEN_SENTINEL" not in str(diagnostic).encode()


@pytest.mark.parametrize(
    ("assignment", "category"),
    [
        (b"cookie=never-print-this-cookie", "COOKIE"),
        (b"token=never-print-this-token", "TOKEN"),
        (b"secret=never-print-this-secret", "CREDENTIAL"),
    ],
)
def test_sensitive_rejection_identifies_only_rule_category_and_line(
    assignment: bytes, category: str
) -> None:
    script = b"#!/bin/sh\npython3 - <<'PY'\nprint('ok')\nPY\n" + assignment + b"\n"

    diagnostic = candidate_rejection_diagnostic(script, "POC_SENSITIVE_CONTENT")

    assert diagnostic["sensitive_category"] == category
    assert diagnostic["sensitive_line"] == 5
    assert b"never-print-this" not in str(diagnostic).encode()


def test_sensitive_rejection_locates_assignment_split_across_lines() -> None:
    script = b"#!/bin/sh\nsecret\n=never-print-this-secret\nprintf x\n"

    diagnostic = candidate_rejection_diagnostic(script, "POC_SENSITIVE_CONTENT")

    assert diagnostic["sensitive_category"] == "CREDENTIAL"
    assert diagnostic["sensitive_line"] == 2
    assert b"never-print-this-secret" not in str(diagnostic).encode()


@pytest.mark.parametrize(
    ("assignment", "category", "rule_id"),
    [
        (b"auth = object()", "CREDENTIAL", "CREDENTIAL_ASSIGNMENT"),
        (b"session_id = object()", "COOKIE", "COOKIE_ASSIGNMENT"),
        (b"token = object()", "TOKEN", "TOKEN_ASSIGNMENT"),
        (
            b"password = never-print-this-password",
            "CREDENTIAL",
            "CREDENTIAL_ASSIGNMENT",
        ),
    ],
)
def test_sensitive_rejection_records_only_closed_rule_id_and_line(
    assignment: bytes, category: str, rule_id: str
) -> None:
    script = b"#!/bin/sh\nprintf ok\n" + assignment + b"\n"

    diagnostic = candidate_rejection_diagnostic(script, "POC_SENSITIVE_CONTENT")

    assert diagnostic["sensitive_category"] == category
    assert diagnostic["sensitive_rule_id"] == rule_id
    assert diagnostic["sensitive_line"] == 3
    assert assignment not in str(diagnostic).encode()
    assert b"never-print-this" not in str(diagnostic).encode()


def test_sensitive_rejection_records_first_rule_without_values() -> None:
    script = (
        b"#!/bin/sh\nauth = never-print-this-password\ntoken = never-print-this-token\n"
    )

    diagnostic = candidate_rejection_diagnostic(script, "POC_SENSITIVE_CONTENT")

    assert diagnostic["sensitive_category"] == "MULTIPLE_RULES"
    assert diagnostic["sensitive_rule_id"] == "CREDENTIAL_ASSIGNMENT"
    assert diagnostic["sensitive_line"] == 2
    assert b"never-print-this" not in str(diagnostic).encode()


def test_rule_diagnostic_does_not_relax_sensitive_candidate_block() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_SENSITIVE_CONTENT"):
        validate_candidate(
            b"#!/bin/sh\nauth=object\nprintf ok\n",
            allowed_environment_names=frozenset(),
        )

    assert validate_candidate(
        b"#!/bin/sh\nsession=object\nprintf ok\n",
        allowed_environment_names=frozenset(),
    )


def test_xml_element_name_without_assignment_is_not_sensitive_content() -> None:
    script = (
        b"#!/bin/sh\npython3 - <<'PY'\n"
        b"from lxml import etree\n"
        b"parser = etree.XMLParser(load_dtd=True)\n"
        b"document = b'<cookie>fixture</cookie>'\n"
        b"print(etree.fromstring(document, parser).tag)\nPY\n"
    )

    assert validate_candidate(script, allowed_environment_names=frozenset())


def test_many_sandbox_paths_round_trip_without_sensitive_rejection() -> None:
    script = b"#!/bin/sh\n" + b"".join(
        f"test -f /workspace/package_{index}/module.py\n".encode()
        for index in range(17)
    )
    encoded = canonical_bytes({"content": script.decode()})

    inspected = inspect_poc_candidate_json(encoded)

    assert inspected.categories == ()
    assert inspected.data == encoded
    assert validate_candidate(script, allowed_environment_names=frozenset())


def test_many_sandbox_paths_do_not_hide_a_secret_assignment() -> None:
    script = (
        b"#!/bin/sh\n"
        + b"".join(
            f"test -f /workspace/package_{index}/module.py\n".encode()
            for index in range(17)
        )
        + b"token=never-print-this-token\n"
    )

    with pytest.raises(PoCCandidateRejected, match="POC_SENSITIVE_CONTENT"):
        validate_candidate(script, allowed_environment_names=frozenset())


@pytest.mark.parametrize(
    "path",
    [
        b"/workspace/sk-abcdefghijklmnop123456",
        b"/workspace/token=never-print-this-token",
        b"/workspace/token= never-print-this-token",
        b"/workspace/authorization: with amber river stone",
    ],
)
def test_sandbox_path_does_not_hide_embedded_secret(path: bytes) -> None:
    script = b"#!/bin/sh\nprintf '%s\\n' '" + path + b"'\n"

    with pytest.raises(PoCCandidateRejected, match="POC_SENSITIVE_CONTENT"):
        validate_candidate(script, allowed_environment_names=frozenset())


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (b"# exit 2 is reserved for harness failures", 0),
        (b"printf '%s\\n' 'exit 2 is reserved for harness failures'", 0),
        (b"printf '%s\\n' observed; exit 2", 1),
    ],
)
def test_rejection_diagnostic_counts_shell_exit_two_lines(
    line: bytes, expected: int
) -> None:
    script = b"#!/bin/sh\n" + line + b"\n"

    diagnostic = candidate_rejection_diagnostic(script, "POC_PLACEHOLDER_FORBIDDEN")

    assert diagnostic["exit_two_line_count"] == expected


def _validate(script: bytes) -> bool:
    return validate_candidate(script, allowed_environment_names=frozenset())


def test_inconclusive_and_runtime_error_in_separate_if_blocks_are_valid() -> None:
    script = (
        b"#!/bin/sh\nstate=fixture\n"
        b'if [ "$state" = inconclusive ]; then\n'
        b"  printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\n"
        b"  exit 0\nfi\n"
        b'if [ "$state" = runtime_error ]; then\n'
        b"  printf '%s\\n' 'RuntimeError: harness failed' >&2\n"
        b"  exit 2\nfi\n"
        b"printf '%s\\n' observed\nexit 0\n"
    )

    assert _validate(script)


def test_inconclusive_and_runtime_error_in_separate_if_arms_are_valid() -> None:
    script = (
        b"#!/bin/sh\nstate=fixture\n"
        b'if [ "$state" = inconclusive ]; then\n'
        b"  printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\n"
        b'  exit 0\nelif [ "$state" = runtime_error ]; then\n'
        b"  printf '%s\\n' 'RuntimeError: harness failed' >&2\n"
        b"  exit 2\nelse\n"
        b"  printf '%s\\n' observed\n"
        b"  exit 0\nfi\n"
    )

    assert _validate(script)


def test_python_heredoc_text_mentioning_exit_two_is_not_a_shell_exit() -> None:
    script = (
        b"#!/bin/sh\npython3 - <<'PY'\n"
        b"note = 'exit 2 is reserved for actual harness errors'\n"
        b"print('SASTSIMI_POC_INCONCLUSIVE')\n"
        b"raise SystemExit(0)\nPY\n"
    )

    assert _validate(script)


def test_python_heredoc_marker_and_shell_runtime_error_exit_are_valid() -> None:
    script = (
        b"#!/bin/sh\npython3 - <<'PY'\n"
        b"try:\n    print('observed')\n"
        b"except RuntimeError:\n    raise\n"
        b"else:\n    print('SASTSIMI_POC_INCONCLUSIVE')\n"
        b"PY\n"
        b"status=$?\n"
        b'if [ "$status" -ne 0 ]\nthen\n'
        b"  printf '%s\\n' 'RuntimeError: harness failed' >&2\n"
        b"  exit 2\nfi\n"
    )

    assert _validate(script)


def test_multiline_shell_if_separates_marker_and_runtime_error_exit() -> None:
    script = (
        b"#!/bin/sh\nstate=unknown\n"
        b'if [ "$state" = unknown ]\nthen\n'
        b"  printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\n"
        b'elif [ "$state" = error ]\nthen\n'
        b"  printf '%s\\n' 'RuntimeError: harness failed' >&2\n"
        b"  exit 2\nelse\n"
        b"  printf '%s\\n' observed\nfi\n"
    )

    assert _validate(script)


@pytest.mark.parametrize(
    "inert_line",
    [
        b"# exit 2 is reserved for harness failures",
        b"printf '%s\\n' observed # exit 2 is reserved for harness failures",
        b"printf '%s\\n' 'exit 2 is reserved for harness failures'",
        b'printf "%s\\n" "exit 2 is reserved for harness failures"',
        b"printf '%s\\n' exit 2",
        b"reason='exit 2 is reserved for harness failures'",
    ],
)
def test_inert_exit_two_mention_does_not_make_inconclusive_marker_a_placeholder(
    inert_line: bytes,
) -> None:
    script = (
        b"#!/bin/sh\n"
        + inert_line
        + b"\nprintf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\nexit 0\n"
    )

    assert _validate(script)


@pytest.mark.parametrize(
    "exit_line",
    [
        b"printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE; exit 2",
        b"printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE && exit 2",
        b"if true; then printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE; exit 2; fi",
    ],
)
def test_inline_shell_exit_two_with_inconclusive_marker_stays_rejected(
    exit_line: bytes,
) -> None:
    script = b"#!/bin/sh\n" + exit_line + b"\n"

    with pytest.raises(PoCCandidateRejected, match="POC_PLACEHOLDER_FORBIDDEN"):
        _validate(script)


@pytest.mark.parametrize(
    "script",
    [
        b"#!/bin/sh\nprintf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\nexit 2\n",
        b"#!/bin/sh\n"
        b"if true; then\n"
        b"  printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\n"
        b"  exit 2\nfi\n",
        b"#!/bin/sh\n"
        b"if true; then\n"
        b"  printf '%s\\n' SASTSIMI_POC_INCONCLUSIVE\n"
        b"  # This comment does not separate commands.\n"
        b"  exit 2\nfi\n",
    ],
)
def test_direct_marker_then_exit_two_stays_rejected(script: bytes) -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_PLACEHOLDER_FORBIDDEN"):
        _validate(script)
