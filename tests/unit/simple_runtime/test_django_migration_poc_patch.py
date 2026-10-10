"""A source-proven Django migration fixture can gain only one false override."""

from __future__ import annotations

import importlib

import pytest

from tests.unit.simple_runtime.test_django_migration_graph_omission import CANDIDATE

FLAG = "HELPDESK_TEAMS_MODE_ENABLED"
CONFIGURE = b"    settings.configure(**settings_values)\n"
OVERRIDE = b"    settings_values['HELPDESK_TEAMS_MODE_ENABLED'] = False\n"


def patch(content: bytes = CANDIDATE, flag: str = FLAG) -> bytes | None:
    try:
        module = importlib.import_module(
            "sastsimi.simple_runtime.django_migration_poc_patch"
        )
    except ModuleNotFoundError:
        return None
    result = module.insert_pinned_django_migration_false_override(content, flag)
    assert result is None or isinstance(result, bytes)
    return result


def test_inserts_exactly_one_override_immediately_before_configure() -> None:
    assert patch() == CANDIDATE.replace(CONFIGURE, OVERRIDE + CONFIGURE)


def test_preserves_crlf_line_endings() -> None:
    content = CANDIDATE.replace(b"\n", b"\r\n")
    expected = content.replace(
        CONFIGURE.replace(b"\n", b"\r\n"),
        (OVERRIDE + CONFIGURE).replace(b"\n", b"\r\n"),
    )
    assert patch(content) == expected


@pytest.mark.parametrize("flag", ["x", "HELPDESK_BAD; rm -rf /", "a\nB", ""])
def test_rejects_nonliteral_flag_name(flag: str) -> None:
    assert patch(flag=flag) is None


@pytest.mark.parametrize(
    "content",
    [
        CANDIDATE.replace(CONFIGURE, OVERRIDE + CONFIGURE),
        CANDIDATE.replace(CONFIGURE, CONFIGURE + CONFIGURE),
        CANDIDATE.replace(CONFIGURE, CONFIGURE.rstrip() + b"; x = 1\n"),
        CANDIDATE.replace(CONFIGURE, CONFIGURE.rstrip() + b"  # comment\n"),
        CANDIDATE.replace(
            b"    settings_values = {",
            b"    unused = '''\n    settings.configure(**settings_values)\n    '''\n"
            b"    settings_values = {",
        ),
    ],
    ids=[
        "already-overridden",
        "duplicate-configure",
        "same-line-statement",
        "inline-comment",
        "line-in-docstring",
    ],
)
def test_rejects_ambiguous_or_previously_modified_content(content: bytes) -> None:
    assert patch(content) is None
