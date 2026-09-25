"""A constant written beside a call is often the whole decision."""

from __future__ import annotations

import ast

from sastsimi.simple_runtime.bootstrap_stages import DirectStaticBootstrap


def _call(source: str) -> ast.Call:
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.Expr)
    assert isinstance(node.value, ast.Call)
    return node.value


def test_the_cap_a_decode_loop_runs_to_is_recorded() -> None:
    # open-webui's _sanitize_proxy_path decodes at most eight times and then
    # proceeds with whatever is left; the advisory is about that number.
    assert DirectStaticBootstrap._literal_arguments(_call("range(8)")) == [8]


def test_strings_are_kept_but_bounded() -> None:
    long = "a" * 200
    assert DirectStaticBootstrap._literal_arguments(_call(f"f({long!r})")) == ["a" * 60]


def test_a_flag_is_not_a_decision_worth_storing() -> None:
    # True and False say nothing about a boundary and every call has them.
    assert DirectStaticBootstrap._literal_arguments(_call("f(True, False)")) == []


def test_a_computed_argument_has_no_constant_to_record() -> None:
    assert DirectStaticBootstrap._literal_arguments(_call("f(limit + 1, g())")) == []


def test_keywords_are_left_alone() -> None:
    # A keyword argument names itself; positional constants are the anonymous
    # ones that are otherwise invisible.
    assert DirectStaticBootstrap._literal_arguments(_call("f(8, cap=9)")) == [8]
