"""Optional-analyzer applicability is a pinned, analyzer-specific proof."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.simple_runtime.attack_surfaces import StaticGap, SurfaceIndex
from sastsimi.simple_runtime.surface_applicability_v9 import (
    assess_optional_analyzers,
    validate_analyzer_applicability,
)

FLASK_APP = b"from flask import Flask\napp = Flask(__name__)\n"
HTTP_HANDLER = b"""from http.server import BaseHTTPRequestHandler as HandlerBase
class Endpoint(HandlerBase):
    def do_GET(self):
        self.send_response(200)
"""
XML_PARSER = b"""import xml.etree.ElementTree as XML
import pkg.endpoints as actions

def build():
    rows = XML.parse('./cfg/routes.xml').findall('mapping')
    routes = []
    for node in rows:
        endpoint = node.findtext('url')
        symbol = node.findtext('type')
        handler = getattr(actions, symbol)
        routes.append((endpoint, handler))
    return routes

if __name__ == '__main__':
    build()
"""
XML_LAUNCHER = (
    b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n"
    b'CMD ["python", "-m", "pkg.dispatch"]\n'
)
XML_CONFIG = (
    b"<root><mapping><url>/catalog</url><type>Catalog</type></mapping></root>\n"
)
XML_FILES = {
    "pkg/__init__.py": b"",
    "pkg/dispatch.py": XML_PARSER,
    "pkg/endpoints.py": b"class Catalog:\n    pass\n",
    "cfg/routes.xml": XML_CONFIG,
    "Dockerfile": XML_LAUNCHER,
}


def _fixture(tmp_path: Path, files: dict[str, bytes]) -> tuple[Path, SurfaceIndex]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    for name, raw in files.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "-c", "core.autocrlf=false", "add", "--", *files],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    hashes = tuple(
        sorted(
            (name, hashlib.sha256(raw).hexdigest())
            for name, raw in files.items()
            if name.endswith((".py", ".pyi"))
        )
    )
    index = SurfaceIndex(
        scope_fingerprint="scope-fixture",
        static_bundle_hash="a" * 64,
        ast_manifest_hash="b" * 64,
        workspace_id="workspace-fixture",
        commit_id=commit,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        surfaces=(),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=hashes,
    )
    return workspace, index


def _statuses(index: SurfaceIndex, workspace: Path) -> tuple[str, str]:
    proof = assess_optional_analyzers(index, workspace)
    assert validate_analyzer_applicability(index, proof, workspace)
    return proof.status_for("stdlib_http"), proof.status_for("operational_xml")


def test_complete_flask_only_manifest_excludes_each_optional_analyzer(
    tmp_path: Path,
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": FLASK_APP})

    proof = assess_optional_analyzers(index, workspace)

    assert _statuses(index, workspace) == ("NOT_APPLICABLE", "NOT_APPLICABLE")
    assert proof.status_for("stdlib_http") == "NOT_APPLICABLE"
    assert proof.status_for("operational_xml") == "NOT_APPLICABLE"
    assert proof.to_json()["commit_id"] == index.commit_id
    assert proof.analyzers[0].source_hashes == index.ast_source_hashes


def test_real_stdlib_handler_does_not_activate_xml_analyzer(tmp_path: Path) -> None:
    workspace, index = _fixture(tmp_path, {"server.py": HTTP_HANDLER})

    assert _statuses(index, workspace) == ("APPLICABLE", "NOT_APPLICABLE")


def test_supported_xml_parser_and_launcher_do_not_activate_http_analyzer(
    tmp_path: Path,
) -> None:
    workspace, index = _fixture(tmp_path, XML_FILES)

    proof = assess_optional_analyzers(index, workspace)

    assert _statuses(index, workspace) == ("NOT_APPLICABLE", "APPLICABLE")
    xml_row = next(row for row in proof.analyzers if row.analyzer == "operational_xml")
    assert ("Dockerfile", hashlib.sha256(XML_LAUNCHER).hexdigest()) in (
        xml_row.source_hashes
    )
    assert ("cfg/routes.xml", hashlib.sha256(XML_CONFIG).hexdigest()) in (
        xml_row.source_hashes
    )


def test_mixed_flask_http_and_xml_sources_keep_both_optional_analyzers(
    tmp_path: Path,
) -> None:
    files = {"app.py": FLASK_APP, "server.py": HTTP_HANDLER, **XML_FILES}
    workspace, index = _fixture(tmp_path, files)

    assert _statuses(index, workspace) == ("APPLICABLE", "APPLICABLE")


def test_one_proven_handler_does_not_hide_a_second_ambiguous_binding(
    tmp_path: Path,
) -> None:
    workspace, index = _fixture(
        tmp_path,
        {
            "server.py": HTTP_HANDLER,
            "alias.py": b"import http.server as http_alias\n"
            b"class Other(http_alias.BaseHTTPRequestHandler):\n    pass\n",
        },
    )

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"


@pytest.mark.parametrize(
    "source",
    [
        b"import importlib\nmodule = importlib.import_module(name)\n",
        b"import http.server as http_alias\n"
        b"class Endpoint(http_alias.BaseHTTPRequestHandler):\n    pass\n",
    ],
)
def test_dynamic_or_unproven_import_cannot_support_absence(
    tmp_path: Path, source: bytes
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": source})

    http_status, xml_status = _statuses(index, workspace)

    assert http_status == "UNKNOWN"
    if b"importlib" in source:
        assert xml_status == "UNKNOWN"


def test_changed_checkout_invalidates_prior_proof_and_never_proves_absence(
    tmp_path: Path,
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": FLASK_APP})
    saved = assess_optional_analyzers(index, workspace)
    (workspace / "app.py").write_bytes(FLASK_APP + b"# changed\n")

    current = assess_optional_analyzers(index, workspace)

    assert not validate_analyzer_applicability(index, saved, workspace)
    assert current.status_for("stdlib_http") == "UNKNOWN"
    assert current.status_for("operational_xml") == "UNKNOWN"
    assert any(
        "MISMATCH" in code for row in current.analyzers for code in row.reason_codes
    )


def test_parse_error_makes_both_analyzers_unknown(tmp_path: Path) -> None:
    workspace, index = _fixture(tmp_path, {"broken.py": b"def broken(:\n"})

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all("SOURCE_PARSE_ERROR" in row.reason_codes for row in proof.analyzers)


def test_scan_file_limit_makes_both_analyzers_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": FLASK_APP})
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_applicability_v9._MAX_SCAN_FILES", 0
    )

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all("SCAN_FILE_LIMIT" in row.reason_codes for row in proof.analyzers)


def test_broken_python_with_ast_gap_blocks_absence_despite_valid_flask_file(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path, {"app.py": FLASK_APP, "server.py": b"def broken(:\n"}
    )
    index = replace(
        complete,
        ast_source_hashes=complete.ast_source_hashes[:1],
        static_gaps=(StaticGap("server.py", "AST", "AST_PARSE_ERROR", "AST"),),
    )

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all("PYTHON_STATIC_GAP" in row.reason_codes for row in proof.analyzers)


def test_omitted_committed_python_handler_blocks_absence_without_static_gap(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path, {"app.py": FLASK_APP, "server.py": HTTP_HANDLER}
    )
    index = replace(complete, ast_source_hashes=complete.ast_source_hashes[:1])

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all(
        "SOURCE_MANIFEST_INCOMPLETE" in row.reason_codes for row in proof.analyzers
    )


def test_excluded_test_sources_do_not_make_product_manifest_incomplete(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path,
        {
            "app.py": FLASK_APP,
            "tests/test_handler.py": HTTP_HANDLER,
            "test_http.py": b"import pytest\n" + HTTP_HANDLER,
            "api/test_client.py": b"# ordinary production code\n",
        },
    )
    index = replace(
        complete,
        ast_source_hashes=tuple(
            row
            for row in complete.ast_source_hashes
            if row[0] in {"app.py", "api/test_client.py"}
        ),
    )

    proof = assess_optional_analyzers(index, workspace)

    assert _statuses(index, workspace) == ("NOT_APPLICABLE", "NOT_APPLICABLE")
    assert proof.analyzers[0].source_hashes == index.ast_source_hashes


def test_omitted_declared_product_entry_in_test_directory_blocks_absence(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path,
        {
            "app.py": FLASK_APP,
            "pyproject.toml": b'[project]\nname="fixture"\n[project.scripts]\n'
            b'fixture = "tests.cli:main"\n',
            "tests/cli.py": b"def main():\n    return 0\n",
        },
    )
    index = replace(
        complete,
        ast_source_hashes=tuple(
            row for row in complete.ast_source_hashes if row[0] == "app.py"
        ),
    )

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all(
        "SOURCE_MANIFEST_INCOMPLETE" in row.reason_codes for row in proof.analyzers
    )


def test_changed_package_manifest_cannot_reclassify_pinned_product_as_test(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path,
        {
            "app.py": FLASK_APP,
            "pyproject.toml": b'[project]\nname="fixture"\n[project.scripts]\n'
            b'fixture = "tests.cli:main"\n',
            "tests/cli.py": b"def main():\n    return 0\n",
        },
    )
    index = replace(
        complete,
        ast_source_hashes=tuple(
            row for row in complete.ast_source_hashes if row[0] == "app.py"
        ),
    )
    (workspace / "pyproject.toml").write_bytes(b'[project]\nname="fixture"\n')

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all(
        "MISMATCH" in code for row in proof.analyzers for code in row.reason_codes
    )


def test_changed_test_fixture_manifests_do_not_block_product_scope_absence(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path,
        {
            "app.py": FLASK_APP,
            "tests/test_app.py": b"import pytest\n",
            "tests/pyproject.toml": b'[project]\nname="fixture"\n',
            "tests/package.json": b'{"name":"fixture"}\n',
        },
    )
    index = replace(
        complete,
        ast_source_hashes=tuple(
            row for row in complete.ast_source_hashes if row[0] == "app.py"
        ),
    )
    (workspace / "tests/pyproject.toml").write_bytes(b"invalid TOML\n")
    (workspace / "tests/package.json").write_bytes(b"invalid JSON\n")

    assert _statuses(index, workspace) == ("NOT_APPLICABLE", "NOT_APPLICABLE")


def test_changed_test_named_product_source_cannot_be_hidden_by_checkout_content(
    tmp_path: Path,
) -> None:
    workspace, complete = _fixture(
        tmp_path,
        {
            "app.py": FLASK_APP,
            "api/test_client.py": b"# deployed client module\n",
        },
    )
    index = replace(
        complete,
        ast_source_hashes=tuple(
            row for row in complete.ast_source_hashes if row[0] == "app.py"
        ),
    )
    (workspace / "api/test_client.py").write_bytes(b"import pytest\n")

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all(
        "MISMATCH" in code for row in proof.analyzers for code in row.reason_codes
    )


@pytest.mark.parametrize(
    "source",
    [
        b"import runpy as runner\nrunner.run_module(module_name)\n",
        b"from runpy import run_path as load\nload(path)\n",
        b"import importlib.util as loader\n"
        b"spec = loader.spec_from_file_location('plugin', path)\n",
        b"from builtins import __import__ as load_module\nload_module(module_name)\n",
        b"from importlib.machinery import SourceFileLoader as Loader\n"
        b"loader = Loader('plugin', path)\n",
    ],
)
def test_dynamic_loaders_and_aliases_block_absence(
    tmp_path: Path, source: bytes
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": source})

    proof = assess_optional_analyzers(index, workspace)

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert proof.status_for("operational_xml") == "UNKNOWN"
    assert all(
        "DYNAMIC_IMPORT_UNRESOLVED" in row.reason_codes for row in proof.analyzers
    )


def test_http_shadowing_and_forged_proof_stay_untrusted(tmp_path: Path) -> None:
    workspace, index = _fixture(
        tmp_path,
        {"server.py": HTTP_HANDLER, "http/__init__.py": b"# shadow\n"},
    )

    proof = assess_optional_analyzers(index, workspace)
    altered = replace(
        proof,
        analyzers=tuple(
            replace(
                row,
                status="NOT_APPLICABLE",
            )
            if row.analyzer == "stdlib_http"
            else row
            for row in proof.analyzers
        ),
    )

    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert not validate_analyzer_applicability(index, altered, workspace)


@pytest.mark.parametrize("tree", ["python", "http"])
def test_transient_pinned_tree_timeout_retries_verified_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tree: str
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": FLASK_APP})
    original_run = subprocess.run
    attempts = 0

    def timeout_once(
        command: tuple[str, ...],
        *,
        stdout: int,
        stderr: int,
        timeout: int,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal attempts
        if "ls-tree" in command and (
            (tree == "python" and "--literal-pathspecs" not in command)
            or (tree == "http" and "http.py" in command)
        ):
            attempts += 1
            if attempts == 1:
                raise subprocess.TimeoutExpired(command, 10)
        return original_run(
            command, stdout=stdout, stderr=stderr, timeout=timeout, check=check
        )

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_applicability_v9.subprocess.run",
        timeout_once,
    )

    proof = assess_optional_analyzers(index, workspace)

    assert attempts == 2
    assert proof.status_for("stdlib_http") == "NOT_APPLICABLE"
    assert proof.status_for("operational_xml") == "NOT_APPLICABLE"


@pytest.mark.parametrize("tree", ["python", "http"])
def test_repeated_pinned_tree_timeout_stays_unknown_after_two_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tree: str
) -> None:
    workspace, index = _fixture(tmp_path, {"app.py": FLASK_APP})
    original_run = subprocess.run
    attempts = 0

    def always_timeout(
        command: tuple[str, ...],
        *,
        stdout: int,
        stderr: int,
        timeout: int,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal attempts
        if "ls-tree" in command and (
            (tree == "python" and "--literal-pathspecs" not in command)
            or (tree == "http" and "http.py" in command)
        ):
            attempts += 1
            raise subprocess.TimeoutExpired(command, 10)
        return original_run(
            command, stdout=stdout, stderr=stderr, timeout=timeout, check=check
        )

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_applicability_v9.subprocess.run",
        always_timeout,
    )

    proof = assess_optional_analyzers(index, workspace)

    assert attempts == 2
    assert proof.status_for("stdlib_http") == "UNKNOWN"
    assert "PINNED_TREE_UNAVAILABLE" in proof.analyzers[0].reason_codes
    assert proof.status_for("operational_xml") == (
        "UNKNOWN" if tree == "python" else "NOT_APPLICABLE"
    )
