"""Bounded Python call-path facts stay separate from taint proof."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.call_path_facts import build_python_call_path_index
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate


def _candidate(path: str, line: int) -> StaticCandidate:
    # The call-path index deliberately needs no artifact contents.  A tiny
    # validated model-shaped placeholder is enough for its location input.
    from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
    from sastsimi.contracts.refs import StoredDataRef

    ref = StoredDataRef(
        data_kind="artifact",
        stored_data_id=StoredDataId("11111111-1111-1111-1111-111111111111"),
        content_hash="a" * 64,
        workspace_id=WorkspaceId("22222222-2222-2222-2222-222222222222"),
        commit_id=CommitId("a" * 40),
        record_id=None,
    )
    return StaticCandidate(
        candidate_id="candidate-1",
        kind="HINT",
        path=path,
        line=line,
        end_line=line,
        evidence_ref=ref,
        origins=(
            CandidateOrigin(
                engine="opengrep",
                rule_id="python.sink",
                artifact_ref=ref,
                result_index=0,
            ),
        ),
        evidence_key="fixture",
    )


def _core_steps(raw_steps: object) -> list[tuple[str, str, int]]:
    """Keep the route/call/sink assertion separate from added source context."""

    assert isinstance(raw_steps, list)
    return [
        (step["role"], step["path"], step["line"])
        for step in raw_steps
        if isinstance(step, dict)
        and step.get("role") in {"ROUTE_ENTRY", "CALL", "SINK"}
    ]


def test_reverse_route_path_resolves_imported_class_method(tmp_path: Path) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "routes.py").write_text(
        "from views import create_student\n"
        "app.add_url_rule('/students', view_func=create_student)\n",
        encoding="utf-8",
    )
    (workspace / "views.py").write_text(
        "from dao.student import Student\n\n"
        "def create_student(name):\n"
        "    return Student.create(name)\n",
        encoding="utf-8",
    )
    dao = workspace / "dao"
    dao.mkdir()
    (dao / "__init__.py").write_text("", encoding="utf-8")
    (dao / "student.py").write_text(
        "class Student:\n"
        "    @classmethod\n"
        "    def create(cls, name):\n"
        "        return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        ("routes.py", "views.py", "dao/__init__.py", "dao/student.py"),
    )
    result = index.for_candidate(_candidate("dao/student.py", 7))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert len(result.paths) == 1
    path = result.paths[0]
    assert path["provenance"] == "python_syntax"
    assert path["assurance"] == "SYNTACTIC_REACHABILITY"
    assert _core_steps(path["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 2),
        ("CALL", "views.py", 4),
        ("CALL", "dao/student.py", 4),
        ("SINK", "dao/student.py", 7),
    ]


def test_source_hint_forward_context_is_cross_file_bounded_and_not_taint_proof(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "from dao import lookup\n"
        "@app.post('/find')\n"
        "async def find(request):\n"
        "    query = await request.json()\n"
        "    return lookup(query)\n",
        encoding="utf-8",
    )
    (workspace / "dao.py").write_text(
        "def lookup(query):\n"
        "    return db.users.find(query)\n\n"
        "def unrelated(query):\n"
        "    return dangerous(query)\n",
        encoding="utf-8",
    )

    result = build_python_call_path_index(
        workspace, ("app.py", "dao.py")
    ).for_candidate(_candidate("app.py", 4), include_downstream=True)

    downstream = [
        path
        for path in result.paths
        if path["kind"] == "candidate_downstream_context_v1"
    ]
    assert len(downstream) == 1
    assert downstream[0]["assurance"] == "SYNTACTIC_REACHABILITY"
    steps = downstream[0]["steps"]
    assert isinstance(steps, list)
    assert ("CALL", "app.py", 5) in {
        (step["role"], step["path"], step["line"]) for step in steps
    }
    assert ("CALLEE_BODY_LINE", "dao.py", 2) in {
        (step["role"], step["path"], step["line"]) for step in steps
    }
    assert not any(step["line"] == 5 and step["path"] == "dao.py" for step in steps)


def test_sink_enclosing_context_shows_preceding_query_construction(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "student.py").write_text(
        "class Student:\n"
        "    @staticmethod\n"
        "    async def create(conn, name):\n"
        '        q = ("INSERT INTO students (name) "\n'
        "             \"VALUES ('%(name)s')\" % {'name': name})\n"
        "        async with conn.cursor() as cur:\n"
        "            await cur.execute(q)\n",
        encoding="utf-8",
    )
    index = build_python_call_path_index(workspace, ("student.py",))
    candidate = _candidate("student.py", 7)
    old = index.for_candidate(candidate, include_enclosing=False)
    new = index.for_candidate(candidate, include_enclosing=True)

    assert not any(
        path["kind"] == "candidate_enclosing_context_v1" for path in old.paths
    )
    enclosing = [
        path for path in new.paths if path["kind"] == "candidate_enclosing_context_v1"
    ]
    assert len(enclosing) == 1
    assert enclosing[0]["assurance"] == "SOURCE_CONTEXT_ONLY"
    enclosing_steps = enclosing[0]["steps"]
    assert isinstance(enclosing_steps, list)
    assert {step["line"] for step in enclosing_steps} >= {3, 4, 5, 6, 7}


def test_aiohttp_add_route_resolves_third_positional_handler(tmp_path: Path) -> None:
    """aiohttp add_route(method, path, handler) reaches the handler and sink."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "routes.py").write_text(
        "from views import create_student\n"
        "app.router.add_route('POST', '/students', create_student)\n",
        encoding="utf-8",
    )
    (workspace / "views.py").write_text(
        "from dao.student import create\n\n"
        "async def create_student(request):\n"
        "    return await create(request)\n",
        encoding="utf-8",
    )
    dao = workspace / "dao"
    dao.mkdir()
    (dao / "__init__.py").write_text("", encoding="utf-8")
    (dao / "student.py").write_text(
        "async def create(request):\n    return await connection.execute(request)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        ("routes.py", "views.py", "dao/__init__.py", "dao/student.py"),
    )
    result = index.for_candidate(_candidate("dao/student.py", 2))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 2),
        ("CALL", "views.py", 4),
        ("SINK", "dao/student.py", 2),
    ]


def test_flask_add_url_rule_uses_view_func_not_endpoint(tmp_path: Path) -> None:
    """A Flask endpoint label is metadata, not the callable route target."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n\n"
        "app.add_url_rule('/students', endpoint='students.create', view_func=create)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("app.py",))
    result = index.for_candidate(_candidate("app.py", 5))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "app.py", 7),
        ("CALL", "app.py", 2),
        ("SINK", "app.py", 5),
    ]


@pytest.mark.parametrize(
    "route_import", ("from sqli import views", "from . import views")
)
def test_nested_package_imports_resolve_route_to_sink(
    tmp_path: Path, route_import: str
) -> None:
    """Nested absolute and relative package imports retain their semantics."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "sqli"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "routes.py").write_text(
        f"{route_import}\napp.router.add_route('POST', '/students', views.students)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "from sqli.dao.student import Student\n\n"
        "async def students(request):\n"
        "    data = await request.post()\n"
        "    return await Student.create(data['name'])\n",
        encoding="utf-8",
    )
    dao = package / "dao"
    dao.mkdir()
    (dao / "__init__.py").write_text("", encoding="utf-8")
    (dao / "student.py").write_text(
        "class Student:\n"
        "    @classmethod\n"
        "    async def create(cls, name):\n"
        "        return await connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        (
            "sqli/__init__.py",
            "sqli/routes.py",
            "sqli/views.py",
            "sqli/dao/__init__.py",
            "sqli/dao/student.py",
        ),
    )
    result = index.for_candidate(_candidate("sqli/dao/student.py", 4))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    raw_steps = result.paths[0]["steps"]
    assert _core_steps(raw_steps) == [
        ("ROUTE_ENTRY", "sqli/routes.py", 2),
        ("CALL", "sqli/views.py", 5),
        ("SINK", "sqli/dao/student.py", 4),
    ]
    assert isinstance(raw_steps, list)
    assert ("HANDLER_DEFINITION", "sqli/views.py", 3) in {
        (step["role"], step["path"], step["line"])
        for step in raw_steps
        if isinstance(step, dict)
    }
    assert ("REQUEST_CONTEXT", "sqli/views.py", 4) in {
        (step["role"], step["path"], step["line"])
        for step in raw_steps
        if isinstance(step, dict)
    }


def test_package_init_relative_import_resolves_route_to_sink(tmp_path: Path) -> None:
    """A package initializer can register a route through ``from . import``."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from . import views\napp.add_url_rule('/students', view_func=views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "from pkg.sink import execute\n\ndef create(name):\n    return execute(name)\n",
        encoding="utf-8",
    )
    (package / "sink.py").write_text(
        "def execute(name):\n    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("pkg/__init__.py", "pkg/views.py", "pkg/sink.py")
    )
    result = index.for_candidate(_candidate("pkg/sink.py", 2))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "pkg/__init__.py", 2),
        ("CALL", "pkg/views.py", 4),
        ("SINK", "pkg/sink.py", 2),
    ]


def test_plain_dotted_import_resolves_route_to_sink(tmp_path: Path) -> None:
    """``import pkg.views`` retains the imported module prefix for calls."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "import pkg.views\napp.add_url_rule('/students', view_func=pkg.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "from pkg.sink import execute\n\ndef create(name):\n    return execute(name)\n",
        encoding="utf-8",
    )
    (package / "sink.py").write_text(
        "def execute(name):\n    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py", "pkg/sink.py")
    )
    result = index.for_candidate(_candidate("pkg/sink.py", 2))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 2),
        ("CALL", "pkg/views.py", 4),
        ("SINK", "pkg/sink.py", 2),
    ]


def test_dotted_import_does_not_resolve_an_unimported_sibling(
    tmp_path: Path,
) -> None:
    """A dotted import cannot prove that a different sibling is available."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "import pkg.views\napp.add_url_rule('/admin', view_func=pkg.admin.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n    return name\n",
        encoding="utf-8",
    )
    (package / "admin.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        ("routes.py", "pkg/__init__.py", "pkg/views.py", "pkg/admin.py"),
    )
    result = index.for_candidate(_candidate("pkg/admin.py", 5))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in result.gaps


@pytest.mark.parametrize(
    "first_import", ("import pkg.views", "import pkg.views as view_module")
)
def test_root_import_keeps_previously_imported_child_available(
    tmp_path: Path, first_import: str
) -> None:
    """A later root import must not erase an already loaded child module."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        f"{first_import}\n"
        "import pkg\n"
        "app.add_url_rule('/students', view_func=pkg.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 3),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_root_alias_keeps_child_loaded_by_later_dotted_import(
    tmp_path: Path,
) -> None:
    """A submodule load attaches the child to an earlier root-package alias."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "import pkg as package\n"
        "import pkg.views\n"
        "app.add_url_rule('/students', view_func=package.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 3),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_root_alias_keeps_child_loaded_by_from_import(tmp_path: Path) -> None:
    """A ``from`` submodule import also attaches the child to a root alias."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "import pkg as package\n"
        "from pkg.views import create\n"
        "app.add_url_rule('/students', view_func=package.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 3),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_root_import_keeps_child_loaded_through_from_import(tmp_path: Path) -> None:
    """A package child imported with ``from`` remains available on its root."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "from pkg import views\n"
        "import pkg\n"
        "app.add_url_rule('/students', view_func=pkg.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 3),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_namespace_root_import_keeps_aliased_dotted_child_available(
    tmp_path: Path,
) -> None:
    """An implicit namespace root can expose a child loaded through an alias."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (workspace / "routes.py").write_text(
        "import pkg.views as view_module\n"
        "import pkg\n"
        "app.add_url_rule('/students', view_func=pkg.views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("routes.py", "pkg/views.py"))
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 3),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_dotted_import_rejects_regular_module_intermediate_prefix(
    tmp_path: Path,
) -> None:
    """A regular module cannot be an importable child-package prefix."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "sub.py").write_text("", encoding="utf-8")
    child = package / "sub"
    child.mkdir()
    (workspace / "routes.py").write_text(
        "import pkg.sub.handler\n"
        "app.add_url_rule('/run', view_func=pkg.sub.handler.create)\n",
        encoding="utf-8",
    )
    (child / "handler.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        (
            "routes.py",
            "pkg/__init__.py",
            "pkg/sub.py",
            "pkg/sub/handler.py",
        ),
    )
    result = index.for_candidate(_candidate("pkg/sub/handler.py", 5))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in result.gaps


def test_dotted_import_prefers_package_over_same_named_module(tmp_path: Path) -> None:
    """Import resolution uses ``pkg/sub/__init__.py`` before ``pkg/sub.py``."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "sub.py").write_text("", encoding="utf-8")
    subpackage = package / "sub"
    subpackage.mkdir()
    (subpackage / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "import pkg.sub.handler\n"
        "app.add_url_rule('/run', view_func=pkg.sub.handler.create)\n",
        encoding="utf-8",
    )
    (subpackage / "handler.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace,
        (
            "routes.py",
            "pkg/__init__.py",
            "pkg/sub.py",
            "pkg/sub/__init__.py",
            "pkg/sub/handler.py",
        ),
    )
    result = index.for_candidate(_candidate("pkg/sub/handler.py", 5))

    assert result.status == "AVAILABLE", result
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 2),
        ("CALL", "pkg/sub/handler.py", 2),
        ("SINK", "pkg/sub/handler.py", 5),
    ]


def test_package_export_shadows_same_named_child_module(tmp_path: Path) -> None:
    """A package attribute wins over a same-named submodule in ``from`` imports."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("views = object()\n", encoding="utf-8")
    (workspace / "routes.py").write_text(
        "from pkg import views\n"
        "app.add_url_rule('/students', view_func=views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in result.gaps


def test_later_initializer_child_import_overrides_earlier_package_attribute(
    tmp_path: Path,
) -> None:
    """Top-level initializer bindings honor the last runtime-visible assignment."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "views = object()\nimport pkg.views\n",
        encoding="utf-8",
    )
    (workspace / "routes.py").write_text(
        "from pkg import views\n"
        "app.add_url_rule('/students', view_func=views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "routes.py", 2),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_conditional_package_export_is_not_assumed_to_be_child_module(
    tmp_path: Path,
) -> None:
    """A conditional initializer binding leaves child reachability unresolved."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "if use_legacy_views:\n    views = object()\n",
        encoding="utf-8",
    )
    (workspace / "routes.py").write_text(
        "from pkg import views\n"
        "app.add_url_rule('/students', view_func=views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(
        workspace, ("routes.py", "pkg/__init__.py", "pkg/views.py")
    )
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "UNRESOLVED_PACKAGE_EXPORT" in result.gaps


def test_function_parameter_shadowing_does_not_create_module_call_edge(
    tmp_path: Path,
) -> None:
    """A handler parameter named like a module function is not that function."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "@app.get('/students')\n"
        "def handler(sink):\n"
        "    return sink(request.args['name'])\n\n"
        "def sink(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("app.py",))
    result = index.for_candidate(_candidate("app.py", 6))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "UNRESOLVED_LOCAL_SHADOWING" in result.gaps


def test_function_assignment_shadowing_does_not_create_module_call_edge(
    tmp_path: Path,
) -> None:
    """A function-local assignment also wins over a module-level function."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "@app.get('/students')\n"
        "def handler():\n"
        "    sink = lambda value: value\n"
        "    return sink(request.args['name'])\n\n"
        "def sink(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("app.py",))
    result = index.for_candidate(_candidate("app.py", 7))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "UNRESOLVED_LOCAL_SHADOWING" in result.gaps


def test_relative_import_beyond_top_level_does_not_create_route_path(
    tmp_path: Path,
) -> None:
    """Invalid relative imports must not create a syntax reachability edge."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from ..victim import handler\napp.add_url_rule('/run', view_func=handler)\n",
        encoding="utf-8",
    )
    (workspace / "victim.py").write_text(
        "def handler(value):\n"
        "    return execute(value)\n\n"
        "def execute(value):\n"
        "    return connection.execute(value)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("pkg/__init__.py", "victim.py"))
    result = index.for_candidate(_candidate("victim.py", 5))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE" in result.gaps


@pytest.mark.parametrize(
    "route_import", ("from pkg import views", "from . import views")
)
def test_namespace_package_import_resolves_route_to_sink(
    tmp_path: Path, route_import: str
) -> None:
    """Tracked child modules work without a package ``__init__.py`` file."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    package = workspace / "pkg"
    package.mkdir()
    (package / "routes.py").write_text(
        f"{route_import}\napp.add_url_rule('/students', view_func=views.create)\n",
        encoding="utf-8",
    )
    (package / "views.py").write_text(
        "def create(name):\n"
        "    return execute(name)\n\n"
        "def execute(name):\n"
        "    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("pkg/routes.py", "pkg/views.py"))
    result = index.for_candidate(_candidate("pkg/views.py", 5))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert _core_steps(result.paths[0]["steps"]) == [
        ("ROUTE_ENTRY", "pkg/routes.py", 2),
        ("CALL", "pkg/views.py", 2),
        ("SINK", "pkg/views.py", 5),
    ]


def test_request_context_is_bounded_and_records_limit_gap(tmp_path: Path) -> None:
    """A large handler cannot silently expand prompt context without a gap."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    request_reads = "".join(
        f"    value_{index} = await request.post()\n" for index in range(9)
    )
    (workspace / "app.py").write_text(
        "@app.post('/run')\n"
        "async def route(request):\n"
        + request_reads
        + "    return sink(value_0)\n\n"
        + "def sink(value):\n"
        + "    return connection.execute(value)\n",
        encoding="utf-8",
    )
    index = build_python_call_path_index(workspace, ("app.py",))
    result = index.for_candidate(_candidate("app.py", 15))

    assert result.status == "PARTIAL"
    assert "REQUEST_CONTEXT_LINE_LIMIT" in result.gaps
    all_steps = result.paths[0]["steps"]
    assert isinstance(all_steps, list)
    request_steps = [step for step in all_steps if step["role"] == "REQUEST_CONTEXT"]
    assert len(request_steps) == 8
    assert [step["line"] for step in request_steps] == list(range(3, 11))


def test_dynamic_dispatch_is_recorded_as_gap_without_fabricated_path(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "from importlib import import_module\n\n"
        "@app.post('/run')\n"
        "def run(name):\n"
        "    module = import_module('dao')\n"
        "    return getattr(module, 'execute')(name)\n",
        encoding="utf-8",
    )
    (workspace / "dao.py").write_text(
        "def execute(name):\n    return connection.execute(name)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("app.py", "dao.py"))
    result = index.for_candidate(_candidate("dao.py", 2))

    assert result.status == "PARTIAL"
    assert result.paths == ()
    assert "UNRESOLVED_DYNAMIC_DISPATCH" in result.gaps


def test_unrelated_dynamic_dispatch_does_not_degrade_resolved_route_path(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "healthy.py").write_text(
        "@app.post('/run')\n"
        "def run(value):\n"
        "    return sink(value)\n\n"
        "def sink(value):\n"
        "    return execute(value)\n",
        encoding="utf-8",
    )
    (workspace / "unrelated.py").write_text(
        "def plugin(value):\n    return getattr(load_plugin(), 'run')(value)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("healthy.py", "unrelated.py"))
    result = index.for_candidate(_candidate("healthy.py", 6))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert [
        (role, line) for role, _path, line in _core_steps(result.paths[0]["steps"])
    ] == [
        ("ROUTE_ENTRY", 1),
        ("CALL", 3),
        ("SINK", 6),
    ]


def test_same_file_unrelated_dynamic_dispatch_does_not_degrade_resolved_route_path(
    tmp_path: Path,
) -> None:
    """A gap belongs to the enclosing callable, not every candidate in its file."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(
        "@app.post('/run')\n"
        "def run(value):\n"
        "    return sink(value)\n\n"
        "def sink(value):\n"
        "    return execute(value)\n\n"
        "def execute(value):\n"
        "    return connection.execute(value)\n\n"
        "def unrelated_plugin(value):\n"
        "    return getattr(load_plugin(), 'run')(value)\n",
        encoding="utf-8",
    )

    index = build_python_call_path_index(workspace, ("app.py",))
    result = index.for_candidate(_candidate("app.py", 9))

    assert result.status == "AVAILABLE", result
    assert result.gaps == ()
    assert [
        (role, line) for role, _path, line in _core_steps(result.paths[0]["steps"])
    ] == [
        ("ROUTE_ENTRY", 1),
        ("CALL", 3),
        ("CALL", 6),
        ("SINK", 9),
    ]


def test_scanner_flow_is_bounded_and_keeps_tool_proven_assurance(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "web.py").write_text("def route(x):\n    return sink(x)\n")
    (workspace / "sink.py").write_text("def sink(x):\n    return eval(x)\n")
    candidate = _candidate("sink.py", 2).model_copy(
        update={
            "kind": "FLOW",
            "flow_trace": {
                "codeFlows": [
                    {
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "web.py"},
                                                "region": {"startLine": 2},
                                            }
                                        }
                                    },
                                    {
                                        "location": {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "sink.py"},
                                                "region": {"startLine": 2},
                                            }
                                        }
                                    },
                                ]
                            }
                        ]
                    }
                ]
            },
        }
    )

    index = build_python_call_path_index(workspace, ("web.py", "sink.py"))
    result = index.for_candidate(candidate)

    assert result.status == "AVAILABLE"
    scanner = next(path for path in result.paths if path["provenance"] == "scanner")
    assert scanner["assurance"] == "TOOL_PROVEN"
    scanner_steps = scanner["steps"]
    assert isinstance(scanner_steps, list)
    assert [(step["path"], step["line"]) for step in scanner_steps] == [
        ("web.py", 2),
        ("sink.py", 2),
    ]


@pytest.mark.parametrize(
    ("source", "candidate_line", "expected_lines"),
    [
        (
            "@app.get('/config')\n"
            "def config():\n"
            "    value = request.args.get('key')\n"
            "    try:\n"
            "        decoded = bytes.fromhex(value)\n"
            "        selected = decrypt(decoded)\n"
            "    except ValueError as exc:\n"
            "        return str(exc)\n"
            "    return render_template('config.html', selected=selected)\n",
            3,
            [3, 6, 7, 8, 9],
        ),
        (
            "@app.get('/decode')\n"
            "async def decode_route(request):\n"
            "    value = request.query_params.get('value')\n"
            "    try:\n"
            "        decoded = decode(value)\n"
            "        selected = verify(decoded)\n"
            "    except ValueError as exc:\n"
            "        return JSONResponse({'error': str(exc)})\n"
            "    return {'result': selected}\n",
            3,
            [3, 5, 7, 8, 9],
        ),
        (
            "@app.get('/config')\n"
            "def config():\n"
            "    value = request.args.get('key')\n"
            "    if value:\n"
            "        try:\n"
            "            decoded = bytes.fromhex(value)\n"
            "            selected = decrypt(decoded)\n"
            "        except ValueError as exc:\n"
            "            return str(exc)\n"
            "    return render_template('config.html', selected=selected)\n",
            3,
            [3, 7, 8, 9, 10],
        ),
    ],
)
def test_request_validation_error_response_keeps_separate_structural_context(
    tmp_path: Path,
    source: str,
    candidate_line: int,
    expected_lines: list[int],
) -> None:
    """A real request-to-validator-to-response shape is review context, not proof."""

    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    candidate = _candidate("app.py", candidate_line).model_copy(
        update={"kind": "ENTRY_POINT"}
    )

    result = build_python_call_path_index(workspace, ("app.py",)).for_candidate(
        candidate, include_enclosing=True, include_error_response=True
    )

    hints = [
        path
        for path in result.paths
        if path["kind"] == "candidate_error_response_context_v1"
    ]
    assert len(hints) == 1
    assert hints[0]["assurance"] == "SOURCE_CONTEXT_ONLY"
    assert hints[0]["provenance"] == "python_syntax"
    steps = hints[0]["steps"]
    assert isinstance(steps, list)
    assert [step["line"] for step in steps] == expected_lines
    assert [step["role"] for step in steps] == [
        "REQUEST_CONTEXT",
        "VALIDATION_CALL",
        "EXCEPTION_HANDLER",
        "CLIENT_ERROR_RESPONSE",
        "NORMAL_RESPONSE",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "@app.get('/config')\n"
        "def config():\n"
        "    value = request.args.get('key')\n"
        "    try:\n"
        "        selected = decrypt(value)\n"
        "    except ValueError as exc:\n"
        "        return 'invalid input'\n"
        "    return selected\n",
        "@app.get('/config')\n"
        "def config():\n"
        "    value = request.args.get('key')\n"
        "    try:\n"
        "        selected = decrypt('constant')\n"
        "    except ValueError as exc:\n"
        "        return str(exc)\n"
        "    return selected\n",
        "def config():\n"
        "    value = request.args.get('key')\n"
        "    try:\n"
        "        selected = decrypt(value)\n"
        "    except ValueError as exc:\n"
        "        return str(exc)\n"
        "    return selected\n",
    ],
)
def test_error_response_hint_requires_request_flow_reflected_error_and_route(
    tmp_path: Path, source: str
) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    candidate_line = 2 if source.startswith("def ") else 3
    candidate = _candidate("app.py", candidate_line).model_copy(
        update={"kind": "ENTRY_POINT"}
    )

    result = build_python_call_path_index(workspace, ("app.py",)).for_candidate(
        candidate, include_enclosing=True, include_error_response=True
    )

    assert not any(
        path["kind"] == "candidate_error_response_context_v1" for path in result.paths
    )


@pytest.mark.parametrize(
    "interlude",
    [
        "    value: str = 'constant'\n",
        "    value += 'constant'\n",
        "    (value := 'constant')\n",
        "    return 'early'\n",
        "    raise ValueError('early')\n",
        "    if value:\n        return 'early'\n",
    ],
)
def test_error_response_hint_rejects_rebinding_or_exit_before_try(
    tmp_path: Path, interlude: str
) -> None:
    source = (
        "@app.get('/config')\n"
        "def config():\n"
        "    value = request.args.get('key')\n" + interlude + "    try:\n"
        "        selected = decrypt(value)\n"
        "    except ValueError as exc:\n"
        "        return str(exc)\n"
        "    return selected\n"
    )
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    candidate = _candidate("app.py", 3).model_copy(update={"kind": "ENTRY_POINT"})

    result = build_python_call_path_index(workspace, ("app.py",)).for_candidate(
        candidate, include_enclosing=True, include_error_response=True
    )

    assert not any(
        path["kind"] == "candidate_error_response_context_v1" for path in result.paths
    )


@pytest.mark.parametrize(
    "try_body",
    [
        "        value: str = 'constant'\n        selected = decrypt(value)\n",
        "        value += 'constant'\n        selected = decrypt(value)\n",
        "        (value := 'constant')\n        selected = decrypt(value)\n",
        "        return 'early'\n        selected = decrypt(value)\n",
        "        raise ValueError('early')\n        selected = decrypt(value)\n",
        "        if value:\n            return 'early'\n"
        "        selected = decrypt(value)\n",
        "        selected = decrypt(value)\n        return selected\n",
    ],
)
def test_error_response_hint_rejects_unsupported_try_control_flow(
    tmp_path: Path, try_body: str
) -> None:
    source = (
        "@app.get('/config')\n"
        "def config():\n"
        "    value = request.args.get('key')\n"
        "    try:\n" + try_body + "    except ValueError as exc:\n"
        "        return str(exc)\n"
        "    return selected\n"
    )
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text(source, encoding="utf-8")
    candidate = _candidate("app.py", 3).model_copy(update={"kind": "ENTRY_POINT"})

    result = build_python_call_path_index(workspace, ("app.py",)).for_candidate(
        candidate, include_enclosing=True, include_error_response=True
    )

    assert not any(
        path["kind"] == "candidate_error_response_context_v1" for path in result.paths
    )
