"""Conservative generated-PoC layout diagnosis from an executed harness error."""

from __future__ import annotations

from pathlib import Path

from sastsimi.simple_runtime.poc_layout import (
    literal_required_python_path,
    pinned_layout_correction,
)
from tests.simple_runtime.test_poc_urlconf_exhaustion_replay import _checkout

_BODY = """import os
class HarnessError(Exception): pass
try:
    root = '/workspace/src'
    if not os.path.isfile(root + '/project/config/urls.py'):
        raise HarnessError('project_import_layout')
except HarnessError:
    raise
"""


def _script(body: str = _BODY) -> bytes:
    return (
        "#!/bin/sh\ncd /workspace || exit 2\npython - <<'PY'\n" + body + "PY\n"
    ).encode()


def _stderr(line: int = 6) -> bytes:
    return (
        "HarnessError\nTraceback (most recent call last):\n"
        f"  at unresolved_frame:{line}\n"
    ).encode()


def test_literal_harness_source_path_is_classified() -> None:
    assert literal_required_python_path(_script(), _stderr()) == (
        "/workspace/src/project/config/urls.py"
    )
    printed_cd = (
        b"cd /workspace || { printf 'HarnessError: workspace_unavailable\\n"
        b"Traceback: at startup\\n' >&2; exit 2; }"
    )
    actual_preamble = _script().replace(
        b"cd /workspace || exit 2", printed_cd + b"\nexport PYTHONDONTWRITEBYTECODE=1"
    )
    assert literal_required_python_path(actual_preamble, _stderr()) == (
        "/workspace/src/project/config/urls.py"
    )


def test_layout_classifier_fails_closed_on_other_outcomes() -> None:
    assert literal_required_python_path(_script(), b"NoReverseMatch\n") is None
    assert literal_required_python_path(_script(), _stderr(5)) is None
    assert (
        literal_required_python_path(
            _script(_BODY.replace("raise HarnessError", "raise AssertionError")),
            _stderr(),
        )
        is None
    )
    assert (
        literal_required_python_path(
            _script(_BODY.replace("root + '/project/config/urls.py'", "chosen")),
            _stderr(),
        )
        is None
    )
    assert (
        literal_required_python_path(
            _script(_BODY.replace("root = '/workspace/src'", "root = user_root")),
            _stderr(),
        )
        is None
    )
    assert (
        literal_required_python_path(
            _script(
                _BODY.replace(
                    "root = '/workspace/src'",
                    "root = '/workspace/src'\n    root += '/hidden'",
                )
            ),
            _stderr(7),
        )
        is None
    )
    assert (
        literal_required_python_path(
            _script(
                _BODY.replace("try:\n", "os.path.isfile = lambda _: False\ntry:\n")
            ),
            _stderr(7),
        )
        is None
    )
    assert (
        literal_required_python_path(
            _script(_BODY.replace("try:\n", "open('/workspace/test.py', 'w')\ntry:\n")),
            _stderr(7),
        )
        is None
    )
    assert (
        literal_required_python_path(
            b"#!/bin/sh\ntouch /workspace/test.py\n"
            + _script().split(b"#!/bin/sh\n", 1)[1],
            _stderr(),
        )
        is None
    )


def test_layout_classifier_rejects_unproven_prior_calls() -> None:
    for prior in (
        "copyfileobj(source, target)",
        "subprocess.check_call(['touch', '/workspace/test.py'])",
        "os.system('touch /workspace/test.py')",
        "unknown_helper('/workspace/test.py')",
    ):
        body = _BODY.replace("try:\n", f"{prior}\ntry:\n", 1)
        assert literal_required_python_path(_script(body), _stderr(7)) is None

    decorated = _BODY.replace(
        "class HarnessError(Exception): pass",
        "@unknown_helper()\ndef marker(): pass\nclass HarnessError(Exception): pass",
    )
    assert literal_required_python_path(_script(decorated), _stderr(8)) is None
    default_call = _BODY.replace(
        "class HarnessError(Exception): pass",
        "def marker(value=unknown_helper()): pass\nclass HarnessError(Exception): pass",
    )
    assert literal_required_python_path(_script(default_call), _stderr(7)) is None
    custom_error = _BODY.replace(
        "class HarnessError(Exception): pass",
        "class HarnessError(Exception, metaclass=UnknownMeta): pass",
    )
    assert literal_required_python_path(_script(custom_error), _stderr()) is None
    nested_root = _BODY.replace(
        "root = '/workspace/src'",
        "root = '/workspace/src'\n    if True:\n        root = '/workspace/changed'",
    )
    assert literal_required_python_path(_script(nested_root), _stderr(8)) is None


def test_pinned_layout_correction_requires_unique_tracked_python_target(
    tmp_path: Path,
) -> None:
    commit = _checkout(tmp_path)
    root = tmp_path / "data" / "workspaces" / "workspace-1"
    dockerfile = b"FROM python:3.12\nWORKDIR /workspace\nCOPY . /workspace\n"
    assert (
        pinned_layout_correction(
            root,
            commit,
            "/workspace/src/standalone/config/urls.py",
            dockerfile,
        )
        == "/workspace/standalone/config/urls.py"
    )
    assert (
        pinned_layout_correction(
            root, commit, "/workspace/src/standalone/config/urls.py", b""
        )
        is None
    )
    assert (
        pinned_layout_correction(
            root, commit, "/workspace/src/standalone/config/missing.py", dockerfile
        )
        is None
    )
    assert (
        pinned_layout_correction(
            root, "0" * 40, "/workspace/src/standalone/config/urls.py", dockerfile
        )
        is None
    )
