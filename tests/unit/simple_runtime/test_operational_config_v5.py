"""Pinned XML provides route/class facts only after the executable chain is proven."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from sastsimi.simple_runtime.operational_config_v5 import (
    OperationalRouteMap,
    _Gap,
    _verified_blob,
    discover_operational_route_maps,
    load_operational_routes,
)
from sastsimi.simple_runtime.retrieval import _read_pinned_blob

PARSER = b"""import xml.etree.ElementTree as XML
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
TARGET = b"class Catalog:\n    pass\n\nclass Ledger:\n    pass\n"
XML = b"""<root>
  <mapping><url>/catalog</url><type>Catalog</type>
    <good_path>never transmit this lesson</good_path>
    <evil_path>never transmit this exploit</evil_path>
    <source>private answer key</source><sink>private answer key</sink>
    <description>private description</description>
    <objective>private objective</objective>
  </mapping>
  <mapping><url>/ledger</url><type>Ledger</type></mapping>
</root>
"""
LAUNCHER = (
    b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n"
    b'CMD ["python", "-m", "pkg.dispatch"]\n'
)
CLASS_PARSER = b"""import xml.etree.ElementTree as Y
import pkg.endpoints as handlers

class Bucket:
    entries = []
    for item in Y.parse('./cfg/routes.xml').findall('mapping'):
        instance = getattr(handlers, item.findtext('type'))(
            url=item.findtext('url'),
            description=item.findtext('description'),
        )
        entries.append(instance)

    def select(self, path):
        for entry in self.entries:
            if path == entry.url:
                return entry.run()
"""
CLASS_TARGET = b"""class Base:
    def __init__(self, url, description):
        self.url = url

class Catalog(Base):
    def run(self):
        return 'catalog'

class Ledger(Base):
    def run(self):
        return 'ledger'
"""


def _fixture(
    tmp_path: Path,
    *,
    parser: bytes = PARSER,
    xml: bytes = XML,
    target: bytes = TARGET,
    launcher: bytes = LAUNCHER,
    entrypoint: bytes | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> tuple[Path, str]:
    workspace = tmp_path / "checkout"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "cfg").mkdir()
    files = {
        "pkg/__init__.py": b"",
        "pkg/dispatch.py": parser,
        "pkg/endpoints.py": target,
        "cfg/routes.xml": xml,
        "Dockerfile": launcher,
    }
    if entrypoint is not None:
        files["start.py"] = entrypoint
    if extra_files:
        files.update(extra_files)
    for name, body in files.items():
        (workspace / name).parent.mkdir(parents=True, exist_ok=True)
        (workspace / name).write_bytes(body)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "--", *files], check=True)
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
    return workspace, commit


def _load(
    workspace: Path,
    commit: str,
    *,
    runtime_workdir: str | None = "/service",
    max_bytes: int = 131072,
) -> OperationalRouteMap:
    return load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        PARSER,
        "Dockerfile",
        runtime_workdir=runtime_workdir,
        max_bytes=max_bytes,
    )


def test_pinned_renamed_parser_xml_target_and_launcher_form_only_operational_facts(
    tmp_path: Path,
) -> None:
    workspace, commit = _fixture(tmp_path)

    result = _load(workspace, commit)

    assert result.gaps == ()
    assert [
        (item.route, item.module_path, item.class_symbol) for item in result.bindings
    ] == [
        ("/catalog", "pkg.endpoints", "Catalog"),
        ("/ledger", "pkg.endpoints", "Ledger"),
    ]
    first = result.bindings[0]
    assert first.config_path == "cfg/routes.xml"
    assert first.config_sha256 == hashlib.sha256(XML).hexdigest()
    assert first.parser_path == "pkg/dispatch.py"
    assert first.parser_sha256 == hashlib.sha256(PARSER).hexdigest()
    assert first.parser_sites == (5, 7, 8, 9, 10, 11, 12)
    assert first.target_path == "pkg/endpoints.py"
    assert first.target_sha256 == hashlib.sha256(TARGET).hexdigest()
    assert first.launcher_path == "Dockerfile"
    assert first.launcher_sha256 == hashlib.sha256(LAUNCHER).hexdigest()

    serialized = json.dumps(result.to_json(), sort_keys=True)
    assert set(result.to_json()) == {"bindings", "gaps"}
    bindings_payload = result.to_json()["bindings"]
    assert isinstance(bindings_payload, list)
    assert bindings_payload
    first_payload = bindings_payload[0]
    assert isinstance(first_payload, dict)
    assert set(first_payload) == {
        "route",
        "module_path",
        "class_symbol",
        "config_path",
        "config_sha256",
        "parser_path",
        "parser_sha256",
        "parser_sites",
        "target_path",
        "target_sha256",
        "launcher_path",
        "launcher_sha256",
    }
    for hidden in (
        "good_path",
        "evil_path",
        "source",
        "sink",
        "description",
        "objective",
        "never transmit",
        "private answer key",
    ):
        assert hidden not in serialized


@pytest.mark.parametrize(
    ("workdir", "launcher", "expected_gap"),
    [
        (None, LAUNCHER, "RUNTIME_WORKDIR_UNPROVEN"),
        ("/elsewhere", LAUNCHER, "RUNTIME_WORKDIR_UNPROVEN"),
        (
            "/service",
            b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n"
            b'CMD ["python", "other.py"]\n',
            "LAUNCHER_ENTRYPOINT_UNPROVEN",
        ),
        (
            "/service",
            b"FROM python:3.12\nWORKDIR /service\n"
            b'CMD ["python", "-m", "pkg.dispatch"]\n',
            "LAUNCHER_WORKSPACE_UNPROVEN",
        ),
    ],
)
def test_missing_workdir_entrypoint_or_source_copy_is_a_gap(
    tmp_path: Path, workdir: str | None, launcher: bytes, expected_gap: str
) -> None:
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit, runtime_workdir=workdir)

    assert result.bindings == ()
    assert expected_gap in result.gaps


@pytest.mark.parametrize(
    ("launcher", "expected_gap"),
    [
        (LAUNCHER + b"FROM scratch\n", "LAUNCHER_FINAL_STAGE_UNPROVEN"),
        (LAUNCHER + b"FROM\tscratch\n", "LAUNCHER_FINAL_STAGE_UNPROVEN"),
        (
            b"FROM python:3.12 AS build\nWORKDIR /service\nCOPY . .\n"
            b'FROM python:3.12\nCMD ["python", "-m", "pkg.dispatch"]\n',
            "RUNTIME_WORKDIR_UNPROVEN",
        ),
        (
            b"FROM python:3.12 AS build\nCOPY . .\n"
            b"FROM python:3.12\nWORKDIR /service\n"
            b'CMD ["python", "-m", "pkg.dispatch"]\n',
            "LAUNCHER_WORKSPACE_UNPROVEN",
        ),
        (
            b'FROM python:3.12 AS build\nCMD ["python", "-m", "pkg.dispatch"]\n'
            b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n",
            "LAUNCHER_ENTRYPOINT_UNPROVEN",
        ),
    ],
)
def test_multistage_dockerfile_never_uses_previous_stage_as_runtime_evidence(
    tmp_path: Path, launcher: bytes, expected_gap: str
) -> None:
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert expected_gap in result.gaps


def test_independent_final_python_stage_proves_its_own_launcher(tmp_path: Path) -> None:
    launcher = (
        b"FROM python:3.12 AS build\nWORKDIR /build\nCOPY . .\n"
        b"RUN echo build-only\n"
        b"FROM python:3.12 AS runtime\nWORKDIR /service\nCOPY . .\n"
        b'CMD ["python", "-m", "pkg.dispatch"]\n'
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.gaps == ()
    assert [(binding.route, binding.class_symbol) for binding in result.bindings] == [
        ("/catalog", "Catalog"),
        ("/ledger", "Ledger"),
    ]


@pytest.mark.parametrize(
    "mutation",
    (
        b"RUN printf '<root />' > cfg/routes.xml\n",
        b"RUN\tprintf '<root />' > cfg/routes.xml\n",
        b"RUN rm cfg/routes.xml\n",
        b"COPY replacement.xml cfg/routes.xml\n",
        b"ADD replacement.xml cfg/routes.xml\n",
    ),
)
def test_final_stage_content_mutation_cannot_prove_pinned_routes(
    tmp_path: Path, mutation: bytes
) -> None:
    launcher = LAUNCHER.replace(
        b'CMD ["python", "-m", "pkg.dispatch"]\n',
        mutation + b'CMD ["python", "-m", "pkg.dispatch"]\n',
    )
    workspace, commit = _fixture(
        tmp_path,
        launcher=launcher,
        extra_files={"replacement.xml": b"<root />\n"},
    )

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_RUNTIME_CONTENT_UNPROVEN" in result.gaps


@pytest.mark.parametrize("ignore_path", (".dockerignore", "Dockerfile.dockerignore"))
def test_dockerignore_cannot_prove_pinned_routes(
    tmp_path: Path, ignore_path: str
) -> None:
    workspace, commit = _fixture(
        tmp_path,
        extra_files={ignore_path: b"cfg/routes.xml\npkg/endpoints.py\n"},
    )

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_BUILD_CONTEXT_UNPROVEN" in result.gaps


@pytest.mark.parametrize(
    "shadow_path",
    (
        "xml.py",
        "xml/__init__.py",
        "xml/etree/ElementTree.py",
        "pkg/xml.py",
    ),
)
def test_local_xml_import_shadow_cannot_prove_stdlib_parse(
    tmp_path: Path, shadow_path: str
) -> None:
    workspace, commit = _fixture(
        tmp_path,
        extra_files={shadow_path: b"# Local module can shadow stdlib XML\n"},
    )

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "PARSER_XML_IMPORT_UNPROVEN" in result.gaps


def test_pinned_xml_shadow_removed_from_checkout_is_still_a_gap(tmp_path: Path) -> None:
    workspace, commit = _fixture(
        tmp_path,
        extra_files={"xml.py": b"# Pinned shadow\n"},
    )
    (workspace / "xml.py").unlink()

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "PARSER_XML_IMPORT_UNPROVEN" in result.gaps


def test_untracked_xml_shadow_in_build_checkout_is_a_gap(tmp_path: Path) -> None:
    workspace, commit = _fixture(tmp_path)
    (workspace / "xml.py").write_text("# Untracked shadow\n", encoding="utf-8")

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "PARSER_XML_IMPORT_UNPROVEN" in result.gaps


@pytest.mark.parametrize(
    ("import_line", "change_call"),
    [
        (b"import os", b"os.chdir('/elsewhere')"),
        (b"import os", b"os.fchdir(0)"),
        (b"from os import chdir as change", b"change('/elsewhere')"),
        (b"import os", b"getattr(os, 'chdir')('/elsewhere')"),
        (b"import os", b"getattr(os, method)('/elsewhere')"),
    ],
)
def test_relative_xml_path_with_possible_cwd_change_is_a_gap(
    tmp_path: Path, import_line: bytes, change_call: bytes
) -> None:
    parser = PARSER.replace(
        b"import pkg.endpoints as actions\n",
        b"import pkg.endpoints as actions\n" + import_line + b"\n",
    ).replace(
        b"    rows = XML.parse",
        b"    " + change_call + b"\n    rows = XML.parse",
    )
    workspace, commit = _fixture(tmp_path, parser=parser)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "PARSER_CWD_UNPROVEN" in result.gaps


def test_cwd_observation_without_change_keeps_relative_xml_binding(
    tmp_path: Path,
) -> None:
    parser = PARSER.replace(
        b"import pkg.endpoints as actions\n",
        b"import pkg.endpoints as actions\nimport os\n",
    ).replace(
        b"    rows = XML.parse",
        b"    os.getcwd()\n    rows = XML.parse",
    )
    workspace, commit = _fixture(tmp_path, parser=parser)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.gaps == ()
    assert len(result.bindings) == 2


def test_discovery_discloses_unproven_relative_xml_cwd(tmp_path: Path) -> None:
    parser = PARSER.replace(
        b"import pkg.endpoints as actions\n",
        b"import pkg.endpoints as actions\nimport os\n",
    ).replace(
        b"    rows = XML.parse",
        b"    os.chdir('/elsewhere')\n    rows = XML.parse",
    )
    workspace, commit = _fixture(tmp_path, parser=parser)
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(parser).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.bindings == ()
    assert "PARSER_CWD_UNPROVEN" in result.gaps


@pytest.mark.parametrize(
    "rebind",
    (
        b"import pkg.alternate as actions",
        b"from pkg import alternate as actions",
    ),
)
def test_inner_import_cannot_rebind_pinned_target_module(
    tmp_path: Path, rebind: bytes
) -> None:
    parser = PARSER.replace(
        b"    rows = XML.parse",
        b"    " + rebind + b"\n    rows = XML.parse",
    )
    workspace, commit = _fixture(
        tmp_path,
        parser=parser,
        extra_files={"pkg/alternate.py": b"class Catalog: pass\nclass Ledger: pass\n"},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps


@pytest.mark.parametrize(
    "rebind",
    (
        b"import pkg.alternate as actions",
        b"from pkg import alternate as actions",
    ),
)
def test_conditional_module_import_cannot_rebind_pinned_target_module(
    tmp_path: Path, rebind: bytes
) -> None:
    parser = PARSER.replace(
        b"\ndef build():",
        b"\nif True:\n    " + rebind + b"\n\ndef build():",
    )
    workspace, commit = _fixture(
        tmp_path,
        parser=parser,
        extra_files={"pkg/alternate.py": b"class Catalog: pass\nclass Ledger: pass\n"},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps


@pytest.mark.parametrize(
    "rebind",
    (
        b"import pkg.alternate as actions",
        b"from pkg import alternate as actions",
    ),
)
def test_later_direct_import_cannot_rebind_pinned_target_module(
    tmp_path: Path, rebind: bytes
) -> None:
    parser = PARSER + b"\n" + rebind + b"\n"
    workspace, commit = _fixture(
        tmp_path,
        parser=parser,
        extra_files={"pkg/alternate.py": b"class Catalog: pass\nclass Ledger: pass\n"},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps


@pytest.mark.parametrize(
    "name",
    ("pkg/dispatch.py", "pkg/endpoints.py", "cfg/routes.xml", "Dockerfile"),
)
def test_changed_checkout_blob_never_supplies_a_binding(
    tmp_path: Path, name: str
) -> None:
    workspace, commit = _fixture(tmp_path)
    (workspace / name).write_bytes((workspace / name).read_bytes() + b"\nchanged")

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "PINNED_BLOB_MISMATCH" in result.gaps


def test_pinned_blob_cache_reuses_git_only_and_rechecks_live_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, commit = _fixture(tmp_path)
    from sastsimi.simple_runtime import operational_config_v5

    original_read = _read_pinned_blob
    reads = 0

    def counted_read(
        workspace: Path,
        path: str,
        *,
        commit: str,
        git_executable: str,
        remaining: int,
    ) -> tuple[bytes | None, str | None]:
        nonlocal reads
        reads += 1
        return original_read(
            workspace,
            path,
            commit=commit,
            git_executable=git_executable,
            remaining=remaining,
        )

    monkeypatch.setattr(operational_config_v5, "_read_pinned_blob", counted_read)
    cache: dict[tuple[Path, str, str], bytes] = {}
    for _ in range(2):
        raw, digest = _verified_blob(
            workspace, commit, "pkg/dispatch.py", 4096, pinned_cache=cache
        )
        assert raw == PARSER
        assert digest == hashlib.sha256(PARSER).hexdigest()
    assert reads == 1
    with pytest.raises(_Gap, match="SOURCE_TOO_LARGE"):
        _verified_blob(
            workspace,
            commit,
            "pkg/dispatch.py",
            len(PARSER) - 1,
            pinned_cache=cache,
        )
    assert reads == 1
    (workspace / "pkg/dispatch.py").write_bytes(PARSER + b"changed")
    with pytest.raises(_Gap, match="PINNED_BLOB_MISMATCH"):
        _verified_blob(workspace, commit, "pkg/dispatch.py", 4096, pinned_cache=cache)
    assert reads == 1


@pytest.mark.parametrize(
    ("xml", "expected_gap"),
    [
        (
            b"<root><mapping><url>/one</url><type>Catalog</type></mapping>"
            b"<mapping><url>/two</url><type>Catalog</type></mapping></root>",
            "AMBIGUOUS_ROUTE_BINDING",
        ),
        (
            b"<root><mapping><url>/one</url><type>Catalog</type></mapping>"
            b"<mapping><url>/one</url><type>Ledger</type></mapping></root>",
            "AMBIGUOUS_ROUTE_BINDING",
        ),
        (
            b'<!DOCTYPE root [<!ENTITY x "Catalog">]><root>'
            b"<mapping><url>/one</url><type>&x;</type></mapping></root>",
            "XML_DTD_OR_ENTITY",
        ),
    ],
)
def test_ambiguous_or_entity_xml_fails_closed(
    tmp_path: Path, xml: bytes, expected_gap: str
) -> None:
    workspace, commit = _fixture(tmp_path, xml=xml)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert expected_gap in result.gaps


def test_oversized_xml_fails_closed(tmp_path: Path) -> None:
    workspace, commit = _fixture(tmp_path)

    result = _load(workspace, commit, max_bytes=len(XML) - 1)

    assert result.bindings == ()
    assert "XML_TOO_LARGE" in result.gaps


def test_unresolved_getattr_or_missing_append_use_chain_fails_closed(
    tmp_path: Path,
) -> None:
    unresolved = PARSER.replace(
        b"getattr(actions, symbol)", b"getattr(factory, symbol)"
    )
    workspace, commit = _fixture(tmp_path, parser=unresolved)
    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        unresolved,
        "Dockerfile",
        runtime_workdir="/service",
    )
    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps

    no_use = PARSER.replace(b"routes.append((endpoint, handler))", b"pass")
    other_workspace, other_commit = _fixture(tmp_path / "second", parser=no_use)
    no_use_result = load_operational_routes(
        other_workspace,
        other_commit,
        "pkg/dispatch.py",
        no_use,
        "Dockerfile",
        runtime_workdir="/service",
    )
    assert no_use_result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in no_use_result.gaps


def test_duplicate_target_class_fails_closed(tmp_path: Path) -> None:
    target = TARGET + b"\nclass Catalog:\n    pass\n"
    workspace, commit = _fixture(tmp_path, target=target)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "AMBIGUOUS_TARGET_CLASS" in result.gaps


def test_rebound_target_class_fails_closed(tmp_path: Path) -> None:
    target = TARGET + b"\nCatalog = object()\n"
    workspace, commit = _fixture(tmp_path, target=target)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "AMBIGUOUS_TARGET_CLASS" in result.gaps


def test_git_tree_object_cannot_stand_in_for_pinned_commit(tmp_path: Path) -> None:
    workspace, commit = _fixture(tmp_path)
    tree_id = (
        subprocess.check_output(
            ["git", "-C", str(workspace), "rev-parse", f"{commit}^{{tree}}"]
        )
        .decode("ascii")
        .strip()
    )

    result = _load(workspace, tree_id)

    assert result.bindings == ()
    assert "PINNED_COMMIT_INVALID" in result.gaps


def test_pinned_script_import_and_call_links_launcher_to_parser(tmp_path: Path) -> None:
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "start.py"]\n'
    )
    entrypoint = (
        b"import pkg.dispatch as mapping\n"
        b"if __name__ == '__main__':\n"
        b"    mapping.build()\n"
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher, entrypoint=entrypoint)

    result = _load(workspace, commit)

    assert result.gaps == ()
    assert len(result.bindings) == 2


@pytest.mark.parametrize(
    "command",
    (
        b'CMD ["python", "-I", "-m", "pkg.dispatch"]\n',
        b'CMD ["python", "-I", "pkg/dispatch.py"]\n',
    ),
)
def test_isolated_python_cannot_prove_pinned_module_or_script_imports(
    tmp_path: Path, command: bytes
) -> None:
    launcher = b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n" + command
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_ENTRYPOINT_UNPROVEN" in result.gaps


@pytest.mark.parametrize(
    "package_files",
    (
        {"pkg/dispatch/__init__.py": b"# package shadows dispatch.py\n"},
        {
            "pkg/dispatch/__init__.py": b"# package shadows dispatch.py\n",
            "pkg/dispatch/__main__.py": b"# different entrypoint\n",
        },
    ),
)
def test_module_launcher_cannot_prove_file_when_same_named_package_exists(
    tmp_path: Path, package_files: dict[str, bytes]
) -> None:
    workspace, commit = _fixture(tmp_path, extra_files=package_files)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_MODULE_COLLISION_UNPROVEN" in result.gaps


@pytest.mark.parametrize(
    "command",
    (
        b"CMD python -m pkg.dispatch\n",
        b"ENTRYPOINT python -m pkg.dispatch\n",
    ),
)
def test_shell_form_cannot_prove_python_launcher_even_with_custom_shell(
    tmp_path: Path, command: bytes
) -> None:
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nSHELL ["false"]\n' + command
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_ENTRYPOINT_UNPROVEN" in result.gaps


def test_exec_form_ignores_custom_shell_when_linking_parser(tmp_path: Path) -> None:
    launcher = LAUNCHER.replace(
        b'CMD ["python", "-m", "pkg.dispatch"]\n',
        b'SHELL ["false"]\nCMD ["python", "-m", "pkg.dispatch"]\n',
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.gaps == ()
    assert len(result.bindings) == 2


def test_rebound_entrypoint_symbol_does_not_prove_parser_execution(
    tmp_path: Path,
) -> None:
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "start.py"]\n'
    )
    entrypoint = (
        b"import pkg.dispatch as mapping\nmapping = object()\nmapping.build()\n"
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher, entrypoint=entrypoint)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_ENTRYPOINT_UNPROVEN" in result.gaps


def test_rebound_parser_function_does_not_prove_execution(tmp_path: Path) -> None:
    parser = PARSER.replace(
        b"if __name__ == '__main__':",
        b"build = object()\nif __name__ == '__main__':",
    )
    workspace, commit = _fixture(tmp_path, parser=parser)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "LAUNCHER_ENTRYPOINT_UNPROVEN" in result.gaps


def test_custom_append_target_does_not_supply_operational_binding(
    tmp_path: Path,
) -> None:
    parser = PARSER.replace(b"    routes = []", b"    routes = CustomRoutes()")
    workspace, commit = _fixture(tmp_path, parser=parser)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps


def test_malformed_launcher_copy_is_an_explicit_gap(tmp_path: Path) -> None:
    launcher = (
        b"FROM python:3.12\nWORKDIR /service\nCOPY 'unclosed .\n"
        b'CMD ["python", "-m", "pkg.dispatch"]\n'
    )
    workspace, commit = _fixture(tmp_path, launcher=launcher)

    result = _load(workspace, commit)

    assert result.bindings == ()
    assert "LAUNCHER_WORKSPACE_UNPROVEN" in result.gaps


def test_class_body_constructor_route_and_dispatch_use_are_pinned(
    tmp_path: Path,
) -> None:
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "./start.py"]\n'
    )
    entrypoint = (
        b"from pkg.dispatch import Bucket\n"
        b"if __name__ == '__main__':\n"
        b"    Bucket().select('/catalog')\n"
    )
    workspace, commit = _fixture(
        tmp_path,
        parser=CLASS_PARSER,
        target=CLASS_TARGET,
        launcher=launcher,
        entrypoint=entrypoint,
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        CLASS_PARSER,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.gaps == ()
    assert [(binding.route, binding.class_symbol) for binding in result.bindings] == [
        ("/catalog", "Catalog"),
        ("/ledger", "Ledger"),
    ]
    assert result.bindings[0].parser_sites == (6, 7, 8, 11, 15)
    payload = json.dumps(result.to_json())
    for hidden in (
        "good_path",
        "evil_path",
        "source",
        "sink",
        "description",
        "objective",
    ):
        assert hidden not in payload


def test_same_package_root_and_submodule_import_keep_class_binding(
    tmp_path: Path,
) -> None:
    parser = CLASS_PARSER.replace(
        b"import pkg.endpoints as handlers",
        b"import pkg\nimport pkg.endpoints",
    ).replace(b"getattr(handlers,", b"getattr(pkg.endpoints,")
    workspace, commit = _fixture(tmp_path, parser=parser, target=CLASS_TARGET)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.gaps == ()
    assert [(row.route, row.class_symbol) for row in result.bindings] == [
        ("/catalog", "Catalog"),
        ("/ledger", "Ledger"),
    ]


def test_same_root_import_does_not_mask_conflicting_alias(
    tmp_path: Path,
) -> None:
    parser = CLASS_PARSER.replace(
        b"import pkg.endpoints as handlers",
        b"import pkg\nimport pkg.endpoints\nimport decoy as pkg",
    ).replace(b"getattr(handlers,", b"getattr(pkg.endpoints,")
    workspace, commit = _fixture(
        tmp_path,
        parser=parser,
        target=CLASS_TARGET,
        extra_files={"decoy.py": b"# conflicting import identity\n"},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert "DYNAMIC_DISPATCH_UNRESOLVED" in result.gaps


@pytest.mark.parametrize(
    "run_line",
    [
        b"RUN python -V\n",
        b"RUN apt-get update && apt-get install -y \\\n"
        b"  curl \\\n"
        b"  && rm -rf /var/lib/apt/lists/*\n",
    ],
)
def test_benign_git_ignore_and_precopy_run_keep_pinned_sources_visible(
    tmp_path: Path,
    run_line: bytes,
) -> None:
    launcher = (
        b"FROM python:3.12\nWORKDIR /service\n" + run_line + b"COPY . .\n"
        b'CMD ["python", "-m", "pkg.dispatch"]\n'
    )
    workspace, commit = _fixture(
        tmp_path,
        launcher=launcher,
        extra_files={".dockerignore": b".git\n"},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        PARSER,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.gaps == ()
    assert len(result.bindings) == 2


@pytest.mark.parametrize(
    "launcher,ignore",
    [
        (
            b"FROM python:3.12\nWORKDIR /service\nCOPY . .\n"
            b"RUN python -V\n"
            b'CMD ["python", "-m", "pkg.dispatch"]\n',
            b".git\n",
        ),
        (LAUNCHER, b"*.py\n"),
        (
            b"FROM python:3.12\nWORKDIR /service\n"
            b"RUN touch /service/xml.py\nCOPY . .\n"
            b'CMD ["python", "-m", "pkg.dispatch"]\n',
            b".git\n",
        ),
    ],
)
def test_postcopy_mutation_or_source_ignore_still_blocks_binding(
    tmp_path: Path, launcher: bytes, ignore: bytes
) -> None:
    workspace, commit = _fixture(
        tmp_path,
        launcher=launcher,
        extra_files={".dockerignore": ignore},
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        PARSER,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert result.gaps


@pytest.mark.parametrize(
    "parser",
    (
        PARSER.replace(b"    routes = []", b"    actions = object()\n    routes = []"),
        PARSER.replace(b"    routes = []", b"    XML = object()\n    routes = []"),
        PARSER.replace(b"    routes = []", b"    getattr = object()\n    routes = []"),
        PARSER.replace(
            b"    for node in rows:", b"    for node in rows:\n        node = object()"
        ),
    ),
)
def test_shadowed_parser_module_builtin_or_record_cannot_bind_routes(
    tmp_path: Path, parser: bytes
) -> None:
    workspace, commit = _fixture(tmp_path, parser=parser)

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.bindings == ()
    assert result.gaps


def test_second_xml_parse_for_route_index_does_not_hide_bound_constructor(
    tmp_path: Path,
) -> None:
    parser = CLASS_PARSER + (
        b"\nclass Index:\n"
        b"    links = {}\n"
        b"    for item in Y.parse('./cfg/routes.xml').findall('mapping'):\n"
        b"        links[item.findtext('url')] = item.findtext('type')\n"
    )
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "./start.py"]\n'
    )
    workspace, commit = _fixture(
        tmp_path,
        parser=parser,
        target=CLASS_TARGET,
        launcher=launcher,
        entrypoint=b"from pkg.dispatch import Bucket\n",
    )

    result = load_operational_routes(
        workspace,
        commit,
        "pkg/dispatch.py",
        parser,
        "Dockerfile",
        runtime_workdir="/service",
    )

    assert result.gaps == ()
    assert len(result.bindings) == 2


def test_discovery_uses_pinned_manifest_parser_and_literal_launcher_workdir(
    tmp_path: Path,
) -> None:
    workspace, commit = _fixture(tmp_path)
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(PARSER).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
        "pkg/__init__.py": hashlib.sha256(b"").hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.gaps == ()
    assert [(binding.route, binding.class_symbol) for binding in result.bindings] == [
        ("/catalog", "Catalog"),
        ("/ledger", "Ledger"),
    ]
    assert {binding.launcher_path for binding in result.bindings} == {"Dockerfile"}


def test_discovery_accepts_class_body_dispatch_with_separate_entry_script(
    tmp_path: Path,
) -> None:
    launcher = (
        b'FROM python:3.12\nWORKDIR /service\nCOPY . .\nCMD ["python", "start.py"]\n'
    )
    entrypoint = b"from pkg.dispatch import Bucket\n"
    workspace, commit = _fixture(
        tmp_path,
        parser=CLASS_PARSER,
        target=CLASS_TARGET,
        launcher=launcher,
        entrypoint=entrypoint,
    )
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(CLASS_PARSER).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(CLASS_TARGET).hexdigest(),
        "start.py": hashlib.sha256(entrypoint).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.gaps == ()
    assert len(result.bindings) == 2


def test_discovery_rejects_ambiguous_parser_launcher_pairs(tmp_path: Path) -> None:
    workspace, commit = _fixture(tmp_path, extra_files={"Containerfile": LAUNCHER})
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(PARSER).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.bindings == ()
    assert "AMBIGUOUS_OPERATIONAL_ROUTE_SOURCE" in result.gaps


def test_discovery_does_not_infer_build_context_for_nested_launcher(
    tmp_path: Path,
) -> None:
    workspace, commit = _fixture(tmp_path, extra_files={"deploy/Dockerfile": LAUNCHER})
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(PARSER).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.gaps == ()
    assert {binding.launcher_path for binding in result.bindings} == {"Dockerfile"}


def test_discovery_rejects_manifest_hash_mismatch(tmp_path: Path) -> None:
    workspace, commit = _fixture(tmp_path)
    source_hashes = {
        "pkg/dispatch.py": "0" * 64,
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.bindings == ()
    assert "PINNED_BLOB_MISMATCH" in result.gaps


def test_discovery_never_guesses_missing_workdir(tmp_path: Path) -> None:
    launcher = b'FROM python:3.12\nCOPY . .\nCMD ["python", "-m", "pkg.dispatch"]\n'
    workspace, commit = _fixture(tmp_path, launcher=launcher)
    source_hashes = {
        "pkg/dispatch.py": hashlib.sha256(PARSER).hexdigest(),
        "pkg/endpoints.py": hashlib.sha256(TARGET).hexdigest(),
    }

    result = discover_operational_route_maps(workspace, commit, source_hashes)

    assert result.bindings == ()
    assert "RUNTIME_WORKDIR_UNPROVEN" in result.gaps
