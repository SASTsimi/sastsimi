"""A fixed SQL literal is evidence only when its pinned source proves it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.simple_runtime.attack_surfaces import AttackSurface


def _surface(
    *,
    path: str = "app.py",
    symbol: str = "cursor.execute",
    line: int = 1,
    detector: str = "AST",
) -> AttackSurface:
    return AttackSurface(
        surface_id="sql-surface-1",
        type="SQL_EXECUTION",
        path=path,
        symbol=symbol,
        line=line,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector=detector,
    )


def _prove(
    workspace: Path,
    surface: AttackSurface,
    source_sha256: str,
    *,
    column: int | None = None,
    expected_call_name: str | None = "cursor.execute",
) -> dict[str, object] | None:
    try:
        from sastsimi.simple_runtime.surface_safe_sql_literal import (
            prove_fixed_sql_literal,
        )
    except ModuleNotFoundError:
        pytest.fail("the fixed-SQL proof helper has not been implemented")
    return prove_fixed_sql_literal(
        workspace,
        surface,
        source_sha256=source_sha256,
        column=column,
        expected_call_name=expected_call_name,
    )


def _write_source(workspace: Path, source: str, path: str = "app.py") -> str:
    raw = source.encode("utf-8")
    (workspace / path).write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_exact_single_literal_call_returns_bound_proof_without_sql_text(
    tmp_path: Path,
) -> None:
    source_hash = _write_source(
        tmp_path, 'cursor.execute("SELECT password FROM users")\n'
    )

    proof = _prove(tmp_path, _surface(), source_hash, column=0)

    assert proof is not None
    assert proof["kind"] == "simple_fixed_sql_literal_proof_v1"
    assert proof["surface_id"] == "sql-surface-1"
    assert proof["path"] == "app.py"
    assert proof["line"] == 1
    assert proof["column"] == 0
    assert proof["symbol"] == "cursor.execute"
    assert proof["source_sha256"] == source_hash
    assert (
        proof["sql_sha256"] == hashlib.sha256(b"SELECT password FROM users").hexdigest()
    )
    assert proof["sql_shape"] == "FIXED_STRING_LITERAL_SINGLE_ARGUMENT"
    assert "SELECT password FROM users" not in json.dumps(proof)


def test_static_rule_surface_requires_exact_pinned_call_name(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'c.execute("SELECT 1")\n')
    rule_surface = _surface(symbol="sastsimi.python.sql-sink", detector="STATIC_RULE")

    proof = _prove(
        tmp_path,
        rule_surface,
        source_hash,
        expected_call_name="c.execute",
    )

    assert proof is not None
    assert proof["symbol"] == "sastsimi.python.sql-sink"
    assert proof["call_name"] == "c.execute"
    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            column=0,
            expected_call_name="c.execute",
        )
        is None
    )
    assert _prove(tmp_path, rule_surface, source_hash, expected_call_name=None) is None
    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            expected_call_name="cursor.execute",
        )
        is None
    )


def test_static_rule_can_prove_other_pinned_sql_api_names(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'c.executescript("CREATE TABLE t(x)")\n')
    rule_surface = _surface(symbol="sastsimi.python.sql-sink", detector="STATIC_RULE")

    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            expected_call_name="c.executescript",
        )
        is not None
    )


def test_non_sql_callee_cannot_be_selected_as_fixed_sql(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'audit("SELECT 1")\n')
    assert (
        _prove(
            tmp_path,
            _surface(symbol="audit"),
            source_hash,
            expected_call_name="audit",
        )
        is None
    )


def test_static_rule_without_column_rejects_other_calls_on_same_line(
    tmp_path: Path,
) -> None:
    source_hash = _write_source(tmp_path, 'audit("entry"); c.execute("SELECT 1")\n')
    rule_surface = _surface(symbol="sastsimi.python.sql-sink", detector="STATIC_RULE")

    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            expected_call_name="c.execute",
        )
        is None
    )
    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            column=16,
            expected_call_name="c.execute",
        )
        is None
    )


def test_static_rule_cannot_select_unrelated_fixed_call_on_dynamic_sql_line(
    tmp_path: Path,
) -> None:
    source_hash = _write_source(tmp_path, 'audit("SELECT 1"); c.execute(user_sql)\n')
    rule_surface = _surface(symbol="sastsimi.python.sql-sink", detector="STATIC_RULE")

    assert (
        _prove(
            tmp_path,
            rule_surface,
            source_hash,
            expected_call_name="audit",
            column=0,
        )
        is None
    )


def test_without_column_requires_unique_matching_call_on_line(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'cursor.execute("SELECT 1")\n')
    assert _prove(tmp_path, _surface(), source_hash) is not None

    source_hash = _write_source(
        tmp_path, 'cursor.execute("SELECT 1"); cursor.execute("SELECT 2")\n'
    )
    assert _prove(tmp_path, _surface(), source_hash) is None
    assert _prove(tmp_path, _surface(), source_hash, column=0) is not None
    assert _prove(tmp_path, _surface(), source_hash, column=1) is None


def test_full_ast_symbol_must_match_surface_symbol(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'db.cursor().execute("SELECT 1")\n')
    assert (
        _prove(
            tmp_path,
            _surface(symbol="db.cursor().execute"),
            source_hash,
            expected_call_name="db.cursor().execute",
        )
        is not None
    )
    assert (
        _prove(
            tmp_path,
            _surface(symbol="execute"),
            source_hash,
            expected_call_name="db.cursor().execute",
        )
        is None
    )


@pytest.mark.parametrize(
    "source",
    [
        "cursor.execute(query)\n",
        'cursor.execute(f"SELECT {name}")\n',
        'cursor.execute("SELECT 1", params)\n',
        'cursor.execute("SELECT 1", params=())\n',
        "cursor.execute(*args)\n",
        'cursor.execute("SELECT 1", **options)\n',
    ],
)
def test_dynamic_or_parameterized_sql_is_not_fixed_literal_proof(
    tmp_path: Path, source: str
) -> None:
    source_hash = _write_source(tmp_path, source)
    assert _prove(tmp_path, _surface(), source_hash) is None


def test_wrong_source_hash_and_non_sql_surface_fail_closed(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'cursor.execute("SELECT 1")\n')
    assert _prove(tmp_path, _surface(), "0" * 64) is None
    assert _prove(tmp_path, _surface(), source_hash.upper()) is None
    assert _prove(tmp_path, _surface(), "not-a-hash") is None
    assert (
        _prove(
            tmp_path,
            AttackSurface(
                surface_id="other",
                type="FILE_ACCESS",
                path="app.py",
                symbol="cursor.execute",
                line=1,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="AST",
            ),
            source_hash,
        )
        is None
    )


def test_unsafe_paths_and_unparseable_source_fail_closed(tmp_path: Path) -> None:
    source_hash = _write_source(tmp_path, 'cursor.execute("SELECT 1")\n')
    assert _prove(tmp_path, _surface(path="../app.py"), source_hash) is None
    assert (
        _prove(tmp_path, _surface(path=str(tmp_path / "app.py")), source_hash) is None
    )
    assert _prove(tmp_path, _surface(path="app.txt"), source_hash) is None
    broken_hash = _write_source(tmp_path, "cursor.execute(\n")
    assert _prove(tmp_path, _surface(), broken_hash) is None


def test_symlinked_source_is_not_accepted(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    raw = b'cursor.execute("SELECT 1")\n'
    target.write_bytes(raw)
    try:
        (tmp_path / "app.py").symlink_to(target)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")
    assert _prove(tmp_path, _surface(), hashlib.sha256(raw).hexdigest()) is None
