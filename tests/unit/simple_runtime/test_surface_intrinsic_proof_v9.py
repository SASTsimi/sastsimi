"""Intrinsic v9 proofs are exact claims about one pinned syntax location."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import _call_fact
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    SurfaceIndex,
    candidate_inventory_hash,
)
from sastsimi.simple_runtime.candidates import StaticCandidate, normalize_candidate_page
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_evidence_graph_v4 import _id
from sastsimi.simple_runtime.surface_intrinsic_proof_v9 import IntrinsicProofV9

_AST_SHA = "b" * 64
Fixture = tuple[
    SurfaceIndex,
    AttackSurface,
    Path,
    dict[str, object],
    Mapping[str, StaticCandidate],
    SimpleArtifactRepository,
]


def _git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(workspace), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _fixture(
    tmp_path: Path,
    source: str,
    *,
    line: int,
    surface_type: str = "SQL_EXECUTION",
    symbol: str = "sastsimi.python.sql-sink",
    detector: str = "STATIC_RULE",
    candidate_ids: tuple[str, ...] | None = None,
) -> Fixture:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    raw = source.encode("utf-8")
    (workspace / "app.py").write_bytes(raw)
    _git(workspace, "init", "-q")
    _git(workspace, "add", "app.py")
    _git(
        workspace,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    commit = _git(workspace, "rev-parse", "HEAD")
    source_sha = hashlib.sha256(raw).hexdigest()
    identity = CheckpointIdentity(
        analysis_id="test-analysis",
        workspace_id="workspace-1",
        commit_id=commit,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    scope = "f" * 64
    candidates: dict[str, StaticCandidate] = {}
    evidence_refs: tuple[StoredDataRef, ...] = ()
    if surface_type == "SQL_EXECUTION":
        rule_id = symbol if detector == "STATIC_RULE" else "sastsimi.python.sql-sink"
        row = {
            "check_id": rule_id,
            "path": "app.py",
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 30},
            "extra": {"message": "sql"},
        }
        evidence = artifacts.put_json({"results": [row]})
        candidate = normalize_candidate_page(
            identity,
            scope,
            "opengrep",
            evidence,
            (row,),
            workspace=workspace,
            identity_version="exact-v2",
        )[0]
        candidates[candidate.candidate_id] = candidate
        evidence_refs = (evidence,)
        if candidate_ids is None:
            candidate_ids = (candidate.candidate_id,)
    if candidate_ids is None:
        candidate_ids = ()
    surface = AttackSurface(
        surface_id="surface-1",
        type=surface_type,
        path="app.py",
        symbol=symbol,
        line=line,
        linked_candidate_ids=candidate_ids,
        evidence_refs=evidence_refs,
        detector=detector,
    )
    index = SurfaceIndex(
        scope_fingerprint=scope,
        static_bundle_hash="d" * 64,
        ast_manifest_hash="c" * 64,
        workspace_id="workspace-1",
        commit_id=commit,
        candidate_inventory_hash=candidate_inventory_hash(tuple(candidates.values())),
        candidate_count=len(candidates),
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", source_sha),),
    )
    facts: list[dict[str, object]] = []
    for node in ast.walk(ast.parse(source)):
        fact: dict[str, object] | None = None
        if isinstance(node, ast.Call):
            fact = _call_fact(node, "app.py")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fact = {
                "kind": type(node).__name__,
                "path": "app.py",
                "line": node.lineno,
                "name": node.name,
            }
        if fact is not None:
            facts.append(
                {
                    **fact,
                    "fact_id": _id("fact", ("app.py", fact, source_sha)),
                    "source_sha256": source_sha,
                    "ast_sha256": _AST_SHA,
                }
            )
    graph: dict[str, object] = {
        "kind": "simple_surface_evidence_graph_v5",
        "anchor": {"surface_id": surface.surface_id, "path": "app.py", "line": line},
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": hashlib.sha256(canonical_bytes(index.to_json())).hexdigest(),
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": [
            {"path": "app.py", "source_sha256": source_sha, "ast_sha256": _AST_SHA}
        ],
        "source_lines": [
            {
                "path": "app.py",
                "line": line,
                "source_sha256": source_sha,
                "text": "[redacted]",
            }
        ],
        "ast_facts": facts,
        "nodes": [],
        "edges": [],
        "paths": [],
        "gaps": [],
    }
    return index, surface, workspace, graph, candidates, artifacts


def _prove(fixture: Fixture) -> IntrinsicProofV9 | None:
    from sastsimi.simple_runtime.surface_intrinsic_proof_v9 import (
        prove_intrinsic_surface,
    )

    return prove_intrinsic_surface(
        *fixture[:4], candidates=fixture[4], artifacts=fixture[5]
    )


def _with_candidate(
    fixture: Fixture,
    candidate: StaticCandidate,
    *,
    symbol: str | None = None,
) -> Fixture:
    index, surface, workspace, graph, _candidates, artifacts = fixture
    changed_surface = replace(
        surface,
        linked_candidate_ids=(candidate.candidate_id,),
        symbol=symbol or surface.symbol,
    )
    changed_index = replace(
        index,
        surfaces=(changed_surface,),
        candidate_inventory_hash=candidate_inventory_hash((candidate,)),
    )
    changed_graph = dict(graph)
    changed_graph["index_hash"] = hashlib.sha256(
        canonical_bytes(changed_index.to_json())
    ).hexdigest()
    return (
        changed_index,
        changed_surface,
        workspace,
        changed_graph,
        {candidate.candidate_id: candidate},
        artifacts,
    )


@pytest.mark.parametrize(
    ("call", "line"),
    [
        ('cursor.execute("SELECT 1")', 1),
        ('connection.execute("SELECT 2")', 2),
        ('db.execute("SELECT 3")', 3),
        ('database.execute("SELECT 4")', 4),
        ('cursor.executemany("SELECT 5")', 5),
        ('model.objects.raw("SELECT 6")', 6),
        ('c.execute("SELECT 7")', 7),
    ],
)
def test_fixed_sql_proves_only_the_indexed_call(
    tmp_path: Path, call: str, line: int
) -> None:
    source = "\n" * (line - 1) + call + "\n"
    fixture = _fixture(tmp_path, source, line=line)

    proof = _prove(fixture)

    assert proof is not None
    assert proof.proof_type == "FIXED_SQL_LITERAL"
    assert proof.line == line
    assert proof.commit_id == fixture[0].commit_id
    assert proof.candidate_ids == tuple(fixture[4])
    assert proof.sql_sha256 == hashlib.sha256(f"SELECT {line}".encode()).hexdigest()
    assert "SELECT" not in json.dumps(proof.to_json())
    assert "route_safe" not in proof.to_json()


def test_route_proof_binds_flask_object_decorator_and_function(tmp_path: Path) -> None:
    fixture = _fixture(
        tmp_path,
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            '@app.route("/items")\n'
            "def items():\n"
            '    return "ok"\n'
        ),
        line=3,
        surface_type="REQUEST_ENTRY",
        symbol="app.route",
        detector="AST",
        candidate_ids=(),
    )

    proof = _prove(fixture)

    assert proof is not None
    assert proof.proof_type == "ROUTE_DECLARATION"
    assert proof.function_name == "items"
    assert proof.line == 3
    assert proof.sql_sha256 is None
    assert "downstream_safe" not in proof.to_json()


def test_nonexistent_pinned_commit_cannot_prove_same_checkout_bytes(
    tmp_path: Path,
) -> None:
    index, surface, workspace, graph, candidates, artifacts = _fixture(
        tmp_path,
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        line=3,
        surface_type="REQUEST_ENTRY",
        symbol="app.route",
        detector="AST",
    )
    assert _prove((index, surface, workspace, graph, candidates, artifacts))
    nonexistent = "0" * 40
    changed_index = replace(index, commit_id=nonexistent)
    changed_graph = dict(graph)
    changed_graph["index_hash"] = hashlib.sha256(
        canonical_bytes(changed_index.to_json())
    ).hexdigest()
    assert (
        _prove(
            (changed_index, surface, workspace, changed_graph, candidates, artifacts)
        )
        is None
    )


def test_source_bytes_must_be_the_pinned_commits_blob(tmp_path: Path) -> None:
    index, surface, workspace, graph, candidates, artifacts = _fixture(
        tmp_path,
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        line=3,
        surface_type="REQUEST_ENTRY",
        symbol="app.route",
        detector="AST",
    )
    assert _prove((index, surface, workspace, graph, candidates, artifacts))
    changed_raw = (workspace / "app.py").read_bytes() + b"\n"
    (workspace / "app.py").write_bytes(changed_raw)
    changed_sha = hashlib.sha256(changed_raw).hexdigest()
    changed_index = replace(index, ast_source_hashes=(("app.py", changed_sha),))
    changed_graph = dict(graph)
    changed_graph["index_hash"] = hashlib.sha256(
        canonical_bytes(changed_index.to_json())
    ).hexdigest()
    changed_graph["source_files"] = [
        {**graph["source_files"][0], "source_sha256": changed_sha}  # type: ignore[index]
    ]
    changed_graph["source_lines"] = [
        {**graph["source_lines"][0], "source_sha256": changed_sha}  # type: ignore[index]
    ]
    facts = graph["ast_facts"]
    assert isinstance(facts, list)
    changed_graph["ast_facts"] = [
        {
            **fact,
            "fact_id": _id(
                "fact",
                (
                    "app.py",
                    {
                        key: value
                        for key, value in fact.items()
                        if key not in {"fact_id", "source_sha256", "ast_sha256"}
                    },
                    changed_sha,
                ),
            ),
            "source_sha256": changed_sha,
        }
        for fact in facts
    ]
    assert (
        _prove(
            (changed_index, surface, workspace, changed_graph, candidates, artifacts)
        )
        is None
    )


@pytest.mark.parametrize(
    "rebinding",
    [
        "def Flask(*args): return other",
        "class Flask: pass",
        "def app(): pass",
        "class app: pass",
        "def flask(): pass",
        "class flask: pass",
        "import fake as Flask",
    ],
)
def test_route_definition_rebindings_are_unknown(
    tmp_path: Path, rebinding: str
) -> None:
    source = (
        "from flask import Flask\n"
        f"{rebinding}\n"
        "app = Flask(__name__)\n"
        '@app.route("/x")\n'
        "def view(): pass\n"
    )
    fixture = _fixture(
        tmp_path,
        source,
        line=4,
        surface_type="REQUEST_ENTRY",
        symbol="app.route",
        detector="AST",
    )
    assert _prove(fixture) is None


def test_sql_requires_original_candidate_inventory_and_artifact(
    tmp_path: Path,
) -> None:
    from sastsimi.simple_runtime.surface_intrinsic_proof_v9 import (
        prove_intrinsic_surface,
    )

    fixture = _fixture(tmp_path, 'cursor.execute("SELECT 1")\n', line=1)
    assert prove_intrinsic_surface(*fixture[:4]) is None
    assert prove_intrinsic_surface(*fixture[:4], candidates=fixture[4]) is None
    assert prove_intrinsic_surface(*fixture[:4], artifacts=fixture[5]) is None
    assert _prove(fixture) is not None


def test_sql_candidate_id_rule_and_location_must_replay_from_raw_artifact(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, 'cursor.execute("SELECT 1")\n', line=1)
    candidate = next(iter(fixture[4].values()))
    assert _prove(fixture) is not None
    forged_id = candidate.model_copy(update={"candidate_id": "9" * 64})
    assert _prove(_with_candidate(fixture, forged_id)) is None
    forged_rule_id = "evil.sql-sink"
    forged_rule = candidate.model_copy(
        update={
            "origins": (
                candidate.origins[0].model_copy(update={"rule_id": forged_rule_id}),
            )
        }
    )
    assert _prove(_with_candidate(fixture, forged_rule, symbol=forged_rule_id)) is None
    forged_location = candidate.model_copy(update={"start_column": 77})
    assert _prove(_with_candidate(fixture, forged_location)) is None


def test_sql_raw_artifact_content_must_match_evidence_hash(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, 'cursor.execute("SELECT 1")\n', line=1)
    assert _prove(fixture) is not None
    candidate = next(iter(fixture[4].values()))
    artifact_path = fixture[5].artifacts.path_for(candidate.evidence_ref.content_hash)
    artifact_path.write_bytes(b'{"results": []}')
    assert _prove(fixture) is None


@pytest.mark.parametrize(
    "source",
    [
        'audit("SELECT 1"); cursor.execute(user_sql)\n',
        'cursor.execute("SELECT 1"); cursor.execute(user_sql)\n',
        "cursor.execute(user_sql)\n",
        'cursor.execute(f"SELECT {name}")\n',
        'cursor.execute("SELECT " + name)\n',
        'cursor.execute("SELECT 1", params=())\n',
    ],
)
def test_dynamic_or_ambiguous_sql_has_no_intrinsic_proof(
    tmp_path: Path, source: str
) -> None:
    assert _prove(_fixture(tmp_path, source, line=1)) is None


def test_altered_candidate_rule_line_and_source_are_rejected(tmp_path: Path) -> None:
    index, surface, workspace, graph, candidates, artifacts = _fixture(
        tmp_path, 'cursor.execute("SELECT 1")\n', line=1
    )

    for changed in (
        replace(surface, linked_candidate_ids=("candidate-forged",)),
        replace(surface, symbol="sastsimi.python.command-sink"),
        replace(surface, line=2),
    ):
        assert _prove((index, changed, workspace, graph, candidates, artifacts)) is None
    (workspace / "app.py").write_text('cursor.execute("SELECT 2")\n')
    assert _prove((index, surface, workspace, graph, candidates, artifacts)) is None


def test_graph_fact_and_index_binding_cannot_be_swapped(tmp_path: Path) -> None:
    index, surface, workspace, graph, candidates, artifacts = _fixture(
        tmp_path, 'cursor.execute("SELECT 1")\n', line=1
    )
    graph["index_hash"] = "0" * 64
    assert _prove((index, surface, workspace, graph, candidates, artifacts)) is None
    graph["index_hash"] = hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
    facts = graph["ast_facts"]
    assert isinstance(facts, list)
    facts[0]["name"] = "audit"
    assert _prove((index, surface, workspace, graph, candidates, artifacts)) is None


def test_malformed_graph_fails_closed(tmp_path: Path) -> None:
    index, surface, workspace, graph, candidates, artifacts = _fixture(
        tmp_path, 'cursor.execute("SELECT 1")\n', line=1
    )
    graph["unexpected"] = object()
    assert _prove((index, surface, workspace, graph, candidates, artifacts)) is None


@pytest.mark.parametrize(
    "source",
    [
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app = other\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        (
            "from flask import Flask as F\n"
            "app = F(__name__)\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        'app = make_app()\n@app.route("/x")\ndef view(): pass\n',
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            '@alias.route("/x")\n'
            "def view(): pass\n"
        ),
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.route = other\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            'setattr(app, "route", other)\n'
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        (
            "app = Flask(__name__)\n"
            "from flask import Flask\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
        (
            "from flask import Flask\n"
            "from fake import Flask\n"
            "app = Flask(__name__)\n"
            '@app.route("/x")\n'
            "def view(): pass\n"
        ),
    ],
)
def test_route_without_unique_flask_binding_is_unknown(
    tmp_path: Path, source: str
) -> None:
    fixture = _fixture(
        tmp_path,
        source,
        line=source.splitlines().index(
            next(x for x in source.splitlines() if x.startswith("@"))
        )
        + 1,
        surface_type="REQUEST_ENTRY",
        symbol="app.route",
        detector="AST",
        candidate_ids=(),
    )
    assert _prove(fixture) is None


def test_validator_recomputes_exact_proof(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.surface_intrinsic_proof_v9 import (
        validate_intrinsic_proof,
    )

    fixture = _fixture(tmp_path, 'cursor.execute("SELECT 1")\n', line=1)
    proof = _prove(fixture)
    assert proof is not None
    index, surface, workspace, graph, candidates, artifacts = fixture
    assert validate_intrinsic_proof(
        index,
        surface,
        workspace,
        graph,
        proof,
        candidates=candidates,
        artifacts=artifacts,
    )
    assert validate_intrinsic_proof(
        index,
        surface,
        workspace,
        graph,
        proof.to_json(),
        candidates=candidates,
        artifacts=artifacts,
    )
    assert not validate_intrinsic_proof(
        index,
        surface,
        workspace,
        graph,
        replace(proof, commit_id="f" * 40),
        candidates=candidates,
        artifacts=artifacts,
    )
    assert not validate_intrinsic_proof(
        index,
        surface,
        workspace,
        graph,
        replace(proof, sql_sha256="0" * 64),
        candidates=candidates,
        artifacts=artifacts,
    )
