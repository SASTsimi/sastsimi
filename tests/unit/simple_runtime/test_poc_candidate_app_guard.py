"""A saved absent-app failure must only forbid executable reintroductions."""

from __future__ import annotations

import pytest

from sastsimi.simple_runtime.recovery import candidate_app_replay_forbidden


def _candidate(body: str, *, shell_prefix: str = "") -> bytes:
    return (
        "#!/bin/sh\n" + shell_prefix + "python - <<'PY'\n" + body + "\nPY\n"
    ).encode()


def test_python_comment_only_absent_app_name_does_not_forbid_replay() -> None:
    content = _candidate("# invented-app is absent from this checkout\nprint('ready')")

    assert not candidate_app_replay_forbidden(content, "invented-app")


def test_inline_python_comment_only_absent_app_name_does_not_forbid_replay() -> None:
    content = _candidate("print('ready')  # invented-app is absent")

    assert not candidate_app_replay_forbidden(content, "invented-app")


def test_clean_shell_candidate_without_heredoc_remains_allowed() -> None:
    assert not candidate_app_replay_forbidden(
        b"#!/bin/sh\nprintf 'fixture_value\\n'\n", "invented-app"
    )


def test_dynamic_import_cannot_reintroduce_the_absent_app() -> None:
    content = _candidate(
        "name = ''.join(chr(n) for n in "
        "(105, 110, 118, 101, 110, 116, 101, 100, 95, 97, 112, 112))\n"
        "__import__(name)"
    )

    assert candidate_app_replay_forbidden(content, "invented_app")


def test_dynamic_package_manager_module_cannot_install_the_absent_app() -> None:
    content = _candidate(
        "import subprocess, sys\n"
        "module = ''.join(chr(n) for n in (112, 105, 112))\n"
        "action = ''.join(chr(n) for n in (105, 110, 115, 116, 97, 108, 108))\n"
        "name = ''.join(chr(n) for n in "
        "(105, 110, 118, 101, 110, 116, 101, 100, 95, 97, 112, 112))\n"
        "subprocess.run([sys.executable, '-m', module, action, name], check=True)"
    )

    assert candidate_app_replay_forbidden(content, "invented_app")


def test_dynamic_package_manager_module_in_command_variable_is_forbidden() -> None:
    content = _candidate(
        "import subprocess, sys\n"
        "module = ''.join(chr(n) for n in (112, 105, 112))\n"
        "action = ''.join(chr(n) for n in (105, 110, 115, 116, 97, 108, 108))\n"
        "name = ''.join(chr(n) for n in "
        "(105, 110, 118, 101, 110, 116, 101, 100, 95, 97, 112, 112))\n"
        "args = [sys.executable, '-m', module, action, name]\n"
        "subprocess.run(args, check=True)"
    )

    assert candidate_app_replay_forbidden(content, "invented_app")


@pytest.mark.parametrize(
    "flag_assignment",
    [
        "flag = '-' + 'm'\n",
        "flag = ''.join(('-', 'm'))\n",
    ],
)
def test_dynamic_subprocess_mode_cannot_hide_package_install(
    flag_assignment: str,
) -> None:
    content = _candidate(
        "import subprocess, sys\n"
        + flag_assignment
        + "module = ''.join(chr(n) for n in (112, 105, 112))\n"
        "action = ''.join(chr(n) for n in (105, 110, 115, 116, 97, 108, 108))\n"
        "name = ''.join(chr(n) for n in "
        "(105, 110, 118, 101, 110, 116, 101, 100, 95, 97, 112, 112))\n"
        "subprocess.run([sys.executable, flag, module, action, name], check=True)"
    )

    assert candidate_app_replay_forbidden(content, "invented_app")


@pytest.mark.parametrize(
    "sink",
    [
        "import runpy\nrunpy.run_module(name)",
        "exec('import ' + name)",
        "compile('import ' + name, '<poc>', 'exec')",
        "eval('print(' + repr(name) + ')')",
        "import importlib\nimportlib.import_module(name)",
    ],
)
def test_dynamic_code_execution_and_module_loading_remain_forbidden(
    sink: str,
) -> None:
    content = _candidate(
        "name = ''.join(chr(n) for n in "
        "(105, 110, 118, 101, 110, 116, 101, 100, 95, 97, 112, 112))\n" + sink
    )

    assert candidate_app_replay_forbidden(content, "invented_app")


@pytest.mark.parametrize(
    "body",
    [
        "import subprocess, sys\n"
        "subprocess.run([sys.executable, '-c', 'print(1)'], check=True)",
        "import subprocess, sys\n"
        "args = [sys.executable, '-c', 'print(1)']\n"
        "subprocess.run(args, check=True)",
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-m', 'http.server', str(port)])",
    ],
)
def test_normal_python_subprocess_remains_allowed(body: str) -> None:
    assert not candidate_app_replay_forbidden(_candidate(body), "invented_app")


@pytest.mark.parametrize(
    "content",
    [
        _candidate("import invented_app"),
        _candidate("options = {'INSTALLED_APPS': ['invented-app']}"),
        _candidate("message = 'invented-app'"),
        _candidate("message = '# invented-app'"),
        _candidate("print('ready')", shell_prefix="python -m pip install package\n"),
        _candidate(
            "# the app is absent\nprint('ready')",
            shell_prefix="pip install package\n",
        ),
        _candidate("print('ready')", shell_prefix="# invented-app\n"),
    ],
)
def test_executable_app_reference_or_installer_remains_forbidden(
    content: bytes,
) -> None:
    assert candidate_app_replay_forbidden(content, "invented-app")


@pytest.mark.parametrize(
    "content",
    [
        b"#!/bin/sh\npython - <<'PY'\n# harmless comment\n",
        b"#!/bin/sh\n# python - <<'PY'\n# invented-app\nPY\n",
        (
            b"#!/bin/sh\npython - <<'PY'\n# invented-app\nPY\n"
            b"python - <<'SECOND'\nprint('ready')\nSECOND\n"
        ),
        b"#!/bin/sh\npython - <<PY\n# invented-app\nPY\n",
    ],
)
def test_ambiguous_heredoc_remains_forbidden(content: bytes) -> None:
    assert candidate_app_replay_forbidden(content, "invented-app")
