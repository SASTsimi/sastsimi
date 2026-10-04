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
    assert _failure_fingerprint(b"", 127, False) == "exit127"


def test_a_script_that_reports_in_its_own_words_is_told_apart() -> None:
    one = _failure_fingerprint(b"ERROR_TYPE: SetupError no python3\n", 2, False)
    other = _failure_fingerprint(b"ERROR_TYPE: HarnessError no app\n", 2, False)

    assert one != other
