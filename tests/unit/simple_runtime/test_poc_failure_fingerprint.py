from __future__ import annotations

from sastsimi.simple_runtime.stages import _failure_fingerprint


def test_different_errors_get_different_fingerprints() -> None:
    config = b"Traceback...\nTypeError: 'NoneType' object is not callable\n"
    table = (
        b"sqlalchemy.exc.ProgrammingError: (psycopg2.errors.DuplicateTable) "
        b'relation "ix_x" already exists\n'
    )

    one = _failure_fingerprint(config, 2, False)
    assert one != _failure_fingerprint(table, 2, False)


def test_the_same_error_with_other_values_matches() -> None:
    first = b"KeyError: 'EMAIL_DOMAIN'\n"
    second = b"KeyError: 'DB_URI'\n"

    one = _failure_fingerprint(first, 2, False)
    assert one == _failure_fingerprint(second, 2, False)


def test_timeout_and_silent_exit_have_their_own_fingerprints() -> None:
    assert _failure_fingerprint(b"", 2, True) == "timeout"
    assert _failure_fingerprint(b"no traceback here", 127, False) == "exit127"
