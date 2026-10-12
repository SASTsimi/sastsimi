"""V4 surface context must use pinned, redacted source and verified syntax edges."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast, index_ast_manifest
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_evidence_graph_v4 import (
    _enclosing_span,
    extract_surface_graph_v4,
)


def _fixture(
    tmp_path: Path,
    sources: dict[str, str],
    *,
    path: str,
    line: int,
) -> tuple[
    SurfaceIndex,
    AttackSurface,
    dict[str, object],
    dict[str, dict[str, object]],
    Path,
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    for relative, source in sources.items():
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="graph-analysis",
        workspace_id="graph-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    summary = collect_python_ast(
        workspace,
        tuple(sources),
        artifacts,
        max_source_bytes=2 * 1024 * 1024,
    )
    manifest = index_ast_manifest(artifacts, summary)
    evidence_ref = artifacts.put_json({"kind": "graph_test_evidence"})
    surface = AttackSurface(
        surface_id="surface-1",
        type="COMMAND_EXECUTION",
        path=path,
        symbol="python/example-rule",
        line=line,
        linked_candidate_ids=(),
        evidence_refs=(evidence_ref,),
        detector="AST",
    )
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash=hashlib.sha256(canonical_bytes(summary)).hexdigest(),
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=tuple(
            sorted(
                (relative, str(entry["source_sha256"]))
                for relative, entry in manifest.items()
            )
        ),
    )
    return index, surface, summary, manifest, workspace, artifacts


def _graph(
    fixture: tuple[
        SurfaceIndex,
        AttackSurface,
        dict[str, object],
        dict[str, dict[str, object]],
        Path,
        SimpleArtifactRepository,
    ],
    max_nodes: int = 256,
    max_edges: int = 512,
) -> dict[str, object]:
    return extract_surface_graph_v4(*fixture, max_nodes=max_nodes, max_edges=max_edges)


def _rows(payload: dict[str, object], field: str) -> list[dict[str, object]]:
    value = payload[field]
    assert isinstance(value, list)
    rows: list[dict[str, object]] = []
    for row in value:
        assert isinstance(row, dict)
        assert all(isinstance(key, str) for key in row)
        rows.append(row)
    return rows


def test_enclosing_decorated_function_and_orphan_ast_fact_get_real_lines(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        tmp_path,
        {
            "app.py": (
                "@app.route('/item')\n"
                "def handler():\n"
                "    item = request.args.get('id')\n"
                "    return execute(item)\n"
                "\n"
                "def tail():\n"
                "    return audit()\n"
            )
        },
        path="app.py",
        line=4,
    )
    graph = _graph(fixture)

    assert graph["kind"] == "simple_surface_evidence_graph_v4"
    assert graph["anchor"] == {"surface_id": "surface-1", "path": "app.py", "line": 4}
    lines = {(row["path"], row["line"]) for row in _rows(graph, "source_lines")}
    assert {("app.py", line) for line in (1, 2, 3, 4)} <= lines
    assert ("app.py", 7) not in lines
    assert any(
        fact["path"] == "app.py" and fact["line"] == 4 and fact["kind"] == "Call"
        for fact in _rows(graph, "ast_facts")
    )

    _, surface, summary, manifest, workspace, artifacts = fixture
    orphan = replace(surface, line=7)
    orphan_graph = extract_surface_graph_v4(
        replace(fixture[0], surfaces=(orphan,)),
        orphan,
        summary,
        manifest,
        workspace,
        artifacts,
    )
    assert any(
        row["path"] == "app.py" and row["line"] == 7
        for row in _rows(orphan_graph, "source_lines")
    )


def test_enclosing_span_is_whole_decorated_function_not_smallest_statement() -> None:
    tree = ast.parse(
        "@route('/x')\n"
        "def handler():\n"
        "    value = request.args['x']\n"
        "    return dangerous(value)\n"
    )

    assert _enclosing_span(tree, 4) == (1, 4)


def test_verified_cross_file_route_and_direct_callee_are_linked(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {
            "routes.py": (
                "from views import create\n"
                "app.add_url_rule('/create', view_func=create)\n"
            ),
            "views.py": (
                "from dao import execute\n"
                "def create(value):\n"
                "    return execute(value)\n"
            ),
            "dao.py": "def execute(value):\n    return dangerous(value)\n",
        },
        path="dao.py",
        line=2,
    )

    graph = _graph(fixture)

    paths = _rows(graph, "paths")
    assert any(
        [
            (step["role"], step["path"], step["line"])
            for step in _rows(path, "steps")
            if step["role"] in {"ROUTE_ENTRY", "CALL", "SINK"}
        ]
        == [
            ("ROUTE_ENTRY", "routes.py", 2),
            ("CALL", "views.py", 3),
            ("SINK", "dao.py", 2),
        ]
        for path in paths
    )
    assert {row["path"] for row in _rows(graph, "source_files")} >= {
        "routes.py",
        "views.py",
        "dao.py",
    }
    assert all(row["source_sha256"] for row in _rows(graph, "source_files"))
    assert all(row["ast_ref"] for row in _rows(graph, "source_files"))
    assert {"ENTRY", "CALL", "SENSITIVE_OPERATION"} <= {
        edge["type"] for edge in _rows(graph, "edges")
    }


def test_same_name_decoy_dynamic_call_and_cycle_do_not_invent_edges(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        tmp_path,
        {
            "routes.py": (
                "from views import handler\n"
                "app.add_url_rule('/run', view_func=handler)\n"
            ),
            "views.py": (
                "def handler():\n"
                "    return getattr(actions, name)()\n"
                "\n"
                "def unused():\n"
                "    return dangerous()\n"
            ),
            "decoy.py": "def handler():\n    return dangerous()\n",
        },
        path="views.py",
        line=2,
    )

    graph = _graph(fixture)

    assert not any(
        step["path"] == "decoy.py"
        for path in _rows(graph, "paths")
        for step in _rows(path, "steps")
    )
    assert not any(
        step["path"] == "views.py" and step["line"] == 5
        for path in _rows(graph, "paths")
        for step in _rows(path, "steps")
    )
    assert any(
        "DYNAMIC_DISPATCH_UNRESOLVED" in str(gap) for gap in _rows(graph, "gaps")
    )
    assert _graph(fixture) == graph

    cycle_dir = tmp_path / "cycle"
    cycle_dir.mkdir()
    cycle_fixture = _fixture(
        cycle_dir,
        {
            "cycle.py": (
                "@app.route('/cycle')\n"
                "def handler():\n"
                "    return helper()\n"
                "\n"
                "def helper():\n"
                "    return handler()\n"
            )
        },
        path="cycle.py",
        line=6,
    )
    cycle_graph = _graph(cycle_fixture)
    assert cycle_graph == _graph(cycle_fixture)
    assert all(len(_rows(path, "steps")) < 12 for path in _rows(cycle_graph, "paths"))


@pytest.mark.parametrize("mutation", ("changed", "directory", "symlink"))
def test_source_hash_change_or_unsafe_path_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": "def handler():\n    return dangerous()\n"},
        path="app.py",
        line=2,
    )
    source = fixture[4] / "app.py"
    if mutation == "changed":
        source.write_text("def handler():\n    return safe()\n", encoding="utf-8")
    elif mutation == "directory":
        source.unlink()
        source.mkdir()
    else:
        replacement = fixture[4] / "replacement.py"
        replacement.write_text("def handler():\n    return dangerous()\n")
        source.unlink()
        try:
            source.symlink_to(replacement)
        except OSError:
            pytest.skip("Creating symlinks requires Windows developer privileges")

    with pytest.raises(ValueError, match="SOURCE_(HASH_MISMATCH|UNSAFE)"):
        _graph(fixture)


def test_unselected_changed_module_cannot_influence_call_resolution(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        tmp_path,
        {
            "app.py": "def handler():\n    return dangerous()\n",
            "unrelated.py": "def helper():\n    return 1\n",
        },
        path="app.py",
        line=2,
    )
    (fixture[4] / "unrelated.py").write_text(
        "def helper():\n    return dangerous()\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="SOURCE_HASH_MISMATCH"):
        _graph(fixture)


def test_oversize_anchor_records_unavailable_without_reading_raw_line(
    tmp_path: Path,
) -> None:
    fixture = _fixture(
        tmp_path,
        {"app.py": "value = '" + "x" * (2 * 1024 * 1024) + "'\n"},
        path="app.py",
        line=1,
    )

    graph = _graph(fixture)

    assert graph["source_lines"] == []
    assert graph["paths"] == []
    assert {gap["reason"] for gap in _rows(graph, "gaps")} >= {"AST_SOURCE_TOO_LARGE"}


def test_parse_error_anchor_stays_explicitly_unavailable(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        {"broken.py": "def handler(:\n    pass\n"},
        path="broken.py",
        line=1,
    )

    graph = _graph(fixture)

    assert graph["source_lines"] == []
    assert graph["paths"] == []
    assert graph["gaps"] == [{"path": "broken.py", "reason": "AST_PARSE_ERROR"}]


def test_budget_oversize_and_redaction_leave_explicit_gaps(tmp_path: Path) -> None:
    secret = "test-only-secret-marker"
    fixture = _fixture(
        tmp_path,
        {
            "app.py": (
                "@app.route('/x')\n"
                "def handler():\n"
                f"    api_key = '{secret}'\n"
                f"    text = '{'x' * 70000}'\n"
                "    return dangerous(api_key, text)\n"
            )
        },
        path="app.py",
        line=5,
    )

    graph = _graph(fixture, max_nodes=2, max_edges=2)

    assert secret not in json.dumps(graph)
    assert any("CONTEXT_BUDGET_EXHAUSTED" in str(gap) for gap in _rows(graph, "gaps"))
    assert any(
        "ATOMIC_SOURCE_LINE_TOO_LARGE" in str(gap) for gap in _rows(graph, "gaps")
    )
