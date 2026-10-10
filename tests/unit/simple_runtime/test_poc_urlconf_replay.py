"""A generated Django PoC must not mistake its URLConf wiring for a missing route."""

from __future__ import annotations

import pytest

from sastsimi.simple_runtime.recovery import (
    candidate_urlconf_replay_forbidden,
    django_urlconf_reverse_failure,
)


def _candidate(
    *,
    root: str = "helpdesk.urls",
    reverse_line: int = 90,
    extra_lines: tuple[str, ...] = (),
) -> bytes:
    lines = [
        "from django.conf import settings",
        "from django.urls import reverse",
        "print('Pinned follow-up view source matched', flush=True)",
        f"settings.configure(ROOT_URLCONF={root!r})",
    ]
    lines.extend(extra_lines)
    lines.extend("" for _ in range(reverse_line - len(lines) - 1))
    lines.append("reverse('helpdesk:followup_edit', args=[1, 1])")
    lines.append("print('Repository follow-up edit HTTP route resolved')")
    return (
        b"#!/bin/sh\ncd /workspace || exit 2\npython - <<'PY'\n"
        + "\n".join(lines).encode()
        + b"\nPY\n"
    )


_STDERR = (
    b"NoReverseMatch\nTraceback (most recent call last):\n"
    b"  at unresolved_frame:90\n  at reverse:92\n"
)
_STDOUT = b"Pinned follow-up view source matched\n"


def test_identifies_only_the_failed_literal_reverse_and_root() -> None:
    assert django_urlconf_reverse_failure(_STDERR, _STDOUT, _candidate()) == (
        "helpdesk.urls",
        "helpdesk",
        "followup_edit",
        2,
    )


_UNRELATED_INTROSPECTION = (
    "def describe(exc, field):",
    "    getattr(exc, 'detail', None)",
    "    return getattr(getattr(field, 'remote_field', None), 'model', None)",
)


def test_historical_urlconf_evidence_allows_unrelated_getattr_calls() -> None:
    assert django_urlconf_reverse_failure(
        _STDERR,
        _STDOUT,
        _candidate(extra_lines=_UNRELATED_INTROSPECTION),
    ) == ("helpdesk.urls", "helpdesk", "followup_edit", 2)


def test_replay_allows_unrelated_getattr_calls_with_literal_pinned_root() -> None:
    assert not candidate_urlconf_replay_forbidden(
        _candidate(root="standalone.config.urls", extra_lines=_UNRELATED_INTROSPECTION),
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )


def test_uninvoked_helper_prints_are_not_counted_as_stdout() -> None:
    lines = _candidate().decode("utf-8").splitlines()
    lines[8:12] = [
        "def report():",
        "    print('Traceback (sanitized): route')",
        "def inconclusive():",
        "    print('SASTSIMI_POC_INCONCLUSIVE')",
    ]
    candidate = ("\n".join(lines) + "\n").encode("utf-8")
    assert django_urlconf_reverse_failure(_STDERR, _STDOUT, candidate) == (
        "helpdesk.urls",
        "helpdesk",
        "followup_edit",
        2,
    )


@pytest.mark.parametrize(
    ("stderr", "stdout", "candidate"),
    [
        (_STDERR.replace(b"NoReverseMatch", b"ImportError"), _STDOUT, _candidate()),
        (
            _STDERR.replace(b"unresolved_frame:90", b"unresolved_frame:89"),
            _STDOUT,
            _candidate(),
        ),
        (
            _STDERR,
            _STDOUT + b"Repository follow-up edit HTTP route resolved\n",
            _candidate(),
        ),
        (_STDERR, _STDOUT, _candidate(root="other.urls")),
        (
            _STDERR,
            _STDOUT,
            _candidate().replace(
                b"ROOT_URLCONF='helpdesk.urls'", b"ROOT_URLCONF=chosen_urlconf"
            ),
        ),
        (
            _STDERR,
            _STDOUT,
            _candidate().replace(
                b"reverse('helpdesk:followup_edit', args=[1, 1])",
                b"reverse('helpdesk:followup_edit', args=route_args)",
            ),
        ),
        (
            _STDERR,
            _STDOUT,
            _candidate().replace(
                b"reverse('helpdesk:followup_edit', args=[1, 1])",
                b"urlpatterns = []\nreverse('helpdesk:followup_edit', args=[1, 1])",
            ),
        ),
    ],
)
def test_ambiguous_or_unrelated_failure_is_not_a_replay_basis(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> None:
    assert django_urlconf_reverse_failure(stderr, stdout, candidate) is None


def test_replay_forbids_same_direct_app_urlconf_and_dynamic_replacement() -> None:
    failing = ("helpdesk.urls", "helpdesk", "followup_edit", 2)
    assert candidate_urlconf_replay_forbidden(_candidate(), failing)
    assert candidate_urlconf_replay_forbidden(
        _candidate().replace(
            b"ROOT_URLCONF='helpdesk.urls'", b"ROOT_URLCONF=chosen_urlconf"
        ),
        failing,
    )
    assert not candidate_urlconf_replay_forbidden(
        _candidate(root="standalone.config.urls"), failing
    )


def test_replay_requires_a_pinned_project_urlconf() -> None:
    failing = ("helpdesk.urls", "helpdesk", "followup_edit", 2)
    assert candidate_urlconf_replay_forbidden(
        _candidate(root="other.urls"), failing, ("standalone.config.urls",)
    )
    assert not candidate_urlconf_replay_forbidden(
        _candidate(root="standalone.config.urls"),
        failing,
        ("standalone.config.urls",),
    )
    assert candidate_urlconf_replay_forbidden(
        _candidate(root="standalone.config.urls").replace(
            b"helpdesk:followup_edit", b"helpdesk:unrelated_route"
        ),
        failing,
        ("standalone.config.urls",),
    )


def _kwargs_candidate(*statements: str) -> bytes:
    return _candidate(root="standalone.config.urls").replace(
        b"settings.configure(ROOT_URLCONF='standalone.config.urls')",
        "\n".join(statements).encode(),
    )


def test_replay_accepts_one_unchanged_literal_options_dictionary() -> None:
    candidate = _kwargs_candidate(
        "options = {'ROOT_URLCONF': 'standalone.config.urls', 'INSTALLED_APPS': []}",
        "settings.configure(**options)",
    )
    assert not candidate_urlconf_replay_forbidden(
        candidate,
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )


@pytest.mark.parametrize(
    "statements",
    [
        (
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "options['DEBUG'] = True",
            "settings.configure(**options)",
        ),
        (
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "options[key] = True",
            "settings.configure(**options)",
        ),
        (
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "settings.configure(**options)",
        ),
        (
            "options = external_options",
            "settings.configure(**options)",
        ),
        (
            "options = {'ROOT_URLCONF': external_root}",
            "settings.configure(**options)",
        ),
        (
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "options.update({'DEBUG': True})",
            "settings.configure(**options)",
        ),
        (
            "options = {**external_options, 'ROOT_URLCONF': 'standalone.config.urls'}",
            "settings.configure(**options)",
        ),
        (
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "settings.configure(**options, DEBUG=True)",
        ),
    ],
)
def test_replay_rejects_modified_or_dynamic_options_dictionary(
    statements: tuple[str, ...],
) -> None:
    assert candidate_urlconf_replay_forbidden(
        _kwargs_candidate(*statements),
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "settings._wrapped.__dict__.update({'ROOT_' + 'URLCONF': 'helpdesk.urls'})",
        "setattr(settings, 'ROOT_' + 'URLCONF', 'helpdesk.urls')",
        "vars(settings).update({'ROOT_' + 'URLCONF': 'helpdesk.urls'})",
        "settings.__dict__['ROOT_' + 'URLCONF'] = 'helpdesk.urls'",
        (
            "vars(globals()['settings']._wrapped).update("
            "{'ROOT_' + 'URLCONF': 'helpdesk.urls'})"
        ),
        ("bound = settings\nsetattr(bound, 'ROOT_' + 'URLCONF', 'helpdesk.urls')"),
        (
            "import django.conf as conf\n"
            "conf.settings._wrapped.__dict__.update("
            "{'ROOT_' + 'URLCONF': 'helpdesk.urls'})"
        ),
        (
            "from django import conf\n"
            "setattr(conf.settings, 'ROOT_' + 'URLCONF', 'helpdesk.urls')"
        ),
        (
            "from django.conf import settings as alias\n"
            "setattr(alias, 'ROOT_' + 'URLCONF', 'helpdesk.urls')"
        ),
        (
            "import django.conf as conf\n"
            "setattr(getattr(conf, 'set' + 'tings'), "
            "'ROOT_' + 'URLCONF', 'helpdesk.urls')"
        ),
        (
            "import django.conf as conf\n"
            "setattr(getattr(conf, 'settings'), "
            "'ROOT_' + 'URLCONF', 'helpdesk.urls')"
        ),
    ],
)
def test_replay_rejects_indirect_settings_root_mutation(mutation: str) -> None:
    assert candidate_urlconf_replay_forbidden(
        _kwargs_candidate(
            "options = {'ROOT_URLCONF': 'standalone.config.urls'}",
            "settings.configure(**options)",
            mutation,
        ),
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )
