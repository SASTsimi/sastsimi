"""A pinned Flask request import must still be the read's actual binding."""

from __future__ import annotations

import ast

import pytest

from sastsimi.simple_runtime.surface_path_proof_v9 import _request_binding


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "from flask import request\n"
            "def handler():\n"
            "    return request.args.get('key')\n",
            True,
        ),
        (
            "from flask import request as flask_request\n"
            "def handler():\n"
            "    return flask_request.args.get('key')\n",
            True,
        ),
        (
            "from flask import request\n"
            "def handler():\n"
            "    global request\n"
            "    request = Fake()\n"
            "    return request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request as flask_request\n"
            "def handler():\n"
            "    global flask_request\n"
            "    flask_request = Fake()\n"
            "    return flask_request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request as flask_request\n"
            "def outer():\n"
            "    global flask_request\n"
            "    flask_request = Fake()\n"
            "    def handler():\n"
            "        return flask_request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request as flask_request\n"
            "def handler():\n"
            "    del flask_request\n"
            "    return flask_request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request\n"
            "def handler():\n"
            "    def replace():\n"
            "        global request\n"
            "        request = Fake()\n"
            "    replace()\n"
            "    return request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request as flask_request\n"
            "def handler():\n"
            "    def replace():\n"
            "        global flask_request\n"
            "        del flask_request\n"
            "    replace()\n"
            "    return flask_request.args.get('key')\n",
            False,
        ),
        (
            "from flask import request as flask_request\n"
            "def handler():\n"
            "    def unrelated():\n"
            "        flask_request = Fake()\n"
            "    unrelated()\n"
            "    return flask_request.args.get('key')\n",
            True,
        ),
        (
            "from flask import request\n"
            "def handler():\n"
            "    def declare_only():\n"
            "        global request\n"
            "    def unrelated():\n"
            "        request = Fake()\n"
            "    unrelated()\n"
            "    return request.args.get('key')\n",
            True,
        ),
    ],
)
def test_request_read_requires_unmodified_flask_binding(
    source: str, expected: bool
) -> None:
    """Global writes must not silently turn a Fake into a trusted Flask input."""

    line = next(
        number
        for number, text in enumerate(source.splitlines(), 1)
        if "return " in text and ".args.get(" in text
    )
    assert _request_binding(ast.parse(source), line) is expected
