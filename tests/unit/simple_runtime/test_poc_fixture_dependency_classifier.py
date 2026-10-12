"""Narrow source-neutral evidence signatures for fixture dependency replay."""

from __future__ import annotations

import pytest

from sastsimi.simple_runtime.recovery import (
    django_poc_fixture_dependency_failure,
    django_poc_fixture_dependency_recovery_decision,
)

_BULK_CANDIDATE = (
    b"django.setup()\n"
    b"with connection.schema_editor() as editor:\n"
    b"    editor.create_model(model)\n"
    b"print('FIXTURE_SCHEMA current_models_created=12')\n"
    b"User.objects.bulk_create([user])\n"
)
_BULK_STDOUT = b"FIXTURE_SCHEMA current_models_created=12\n"
_BULK_STDERR = (
    b"OperationalError\n"
    b"Traceback (most recent call last):\n"
    b"  frame 1: _insert\n"
    b"  frame 2: execute_sql\n"
    b"  frame 3: execute\n"
    b"  frame 4: _execute_with_wrappers\n"
    b"  frame 5: _execute\n"
    b"  frame 6: __exit__\n"
    b"  frame 7: _execute\n"
    b"  frame 8: execute\n"
)
_USER_CANDIDATE = (
    b"django.setup()\n"
    b"stage = 'database_setup'\n"
    b"with connection.schema_editor() as editor:\n"
    b"    editor.create_model(model)\n"
    b"account = User.objects.create_user(username='fixture')\n"
    b"response = client.get(route)\n"
)
_USER_STDERR = (
    b"OperationalError: harness_runtime\n"
    b"Traceback (function names only):\n"
    b"  in _insert\n"
    b"  in execute_sql\n"
    b"  in execute\n"
    b"  in _execute_with_wrappers\n"
    b"  in _execute\n"
    b"  in __exit__\n"
    b"  in _execute\n"
    b"  in execute\n"
)


def test_bulk_fixture_schema_with_insert_trace_is_classified() -> None:
    assert (
        django_poc_fixture_dependency_failure(
            _BULK_STDERR, _BULK_STDOUT, _BULK_CANDIDATE
        )
        == "fixture dependency after targeted schema setup"
    )


def test_empty_output_user_signal_fixture_setup_failure_is_classified() -> None:
    assert (
        django_poc_fixture_dependency_failure(_USER_STDERR, b"", _USER_CANDIDATE)
        == "fixture dependency after user creation"
    )


@pytest.mark.parametrize(
    ("stderr", "stdout", "candidate"),
    [
        (_USER_STDERR + b"other exception\n", b"", _USER_CANDIDATE),
        (_USER_STDERR.replace(b"in _insert", b"in target_route"), b"", _USER_CANDIDATE),
        (_USER_STDERR, b"target_http=200\n", _USER_CANDIDATE),
        (
            _USER_STDERR,
            b"",
            _USER_CANDIDATE.replace(b"stage = 'database_setup'", b"stage = 'target'"),
        ),
        (
            _USER_STDERR,
            b"",
            _USER_CANDIDATE.replace(b"objects.create_user", b"objects.create"),
        ),
        (
            _USER_STDERR,
            b"",
            _USER_CANDIDATE.replace(b"editor.create_model", b"editor.fake_model"),
        ),
        (
            _USER_STDERR,
            b"",
            _USER_CANDIDATE.replace(
                b"account = User.objects.create_user(username='fixture')\n",
                b"",
            ).replace(
                b"stage = 'database_setup'\n",
                b"stage = 'database_setup'\n"
                b"account = User.objects.create_user(username='fixture')\n",
            ),
        ),
    ],
)
def test_user_signal_fixture_near_misses_do_not_authorize_replay(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> None:
    assert django_poc_fixture_dependency_failure(stderr, stdout, candidate) is None


def test_fixture_recovery_guidance_does_not_assert_an_unobserved_skip() -> None:
    decision = django_poc_fixture_dependency_recovery_decision()

    assert "skipping a schema model" not in decision.diagnosis.lower()
    assert "dependency-complete" in decision.guidance


def test_skipped_model_schema_signature_remains_classified() -> None:
    candidate = (
        b"django.setup()\n"
        b"with connection.schema_editor() as editor: editor.create_model(model)\n"
        b"print('Schema: created=26 skipped_unrelated=1')\n"
        b"phase = 'fixtures'\n"
        b"User.objects.create(username='fixture')\n"
    )
    stderr = (
        b"OperationalError during fixtures\n"
        b"Traceback: execute > _execute_with_wrappers > _execute > __exit__ > "
        b"_execute > execute\n"
    )
    assert (
        django_poc_fixture_dependency_failure(
            stderr, b"Schema: created=26 skipped_unrelated=1\n", candidate
        )
        == "fixture dependency after skipped schema model"
    )


@pytest.mark.parametrize(
    ("stderr", "stdout", "candidate"),
    [
        (b"OperationalError\n", _BULK_STDOUT, _BULK_CANDIDATE),
        (
            b"OperationalError\nTraceback (most recent call last):\n"
            b"  frame 1: _insert\n  frame 2: execute_sql\n",
            _BULK_STDOUT,
            _BULK_CANDIDATE,
        ),
        (_BULK_STDERR + b"private detail\n", _BULK_STDOUT, _BULK_CANDIDATE),
        (_BULK_STDERR, b"FIXTURE_SCHEMA current_models_created=0\n", _BULK_CANDIDATE),
        (_BULK_STDERR, _BULK_STDOUT + b"extra output\n", _BULK_CANDIDATE),
        (
            _BULK_STDERR,
            _BULK_STDOUT,
            _BULK_CANDIDATE.replace(b"objects.bulk_create", b"objects.create"),
        ),
        (
            _BULK_STDERR,
            _BULK_STDOUT,
            _BULK_CANDIDATE.replace(b"schema_editor", b"manual_ddl"),
        ),
        (
            _BULK_STDERR,
            _BULK_STDOUT,
            _BULK_CANDIDATE.replace(b"create_model", b"make_table"),
        ),
        (
            _BULK_STDERR,
            _BULK_STDOUT,
            _BULK_CANDIDATE.replace(b"django.setup(", b"plain_setup("),
        ),
    ],
)
def test_bulk_fixture_near_misses_do_not_authorize_replay(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> None:
    assert django_poc_fixture_dependency_failure(stderr, stdout, candidate) is None
