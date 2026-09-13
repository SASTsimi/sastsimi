"""Reject mutable external workflow actions and retained checkout credentials."""

from __future__ import annotations

import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]


def _workflow_violations(source: str, *, name: str) -> list[str]:
    violations: list[str] = []
    # BaseLoader preserves GitHub-valid mapping keys such as ``on`` and ``yes``
    # instead of applying YAML 1.1 boolean coercion and collapsing them to True.
    pending: list[object] = [yaml.load(source, Loader=yaml.BaseLoader)]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            pending.extend(node.values())
            if "uses" not in node:
                continue
            uses = node["uses"]
            assert isinstance(uses, str), f"{name}: invalid uses value"
            if uses.startswith("./"):
                continue
            action, separator, revision = uses.partition("@")
            if not separator or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                violations.append(f"{name}: mutable external action {uses}")
            if action.lower() == "actions/checkout":
                options = node.get("with", {})
                if (
                    not isinstance(options, dict)
                    or options.get("persist-credentials") != "false"
                ):
                    violations.append(
                        f"{name}: {uses} must set persist-credentials: false"
                    )
    return violations


def test_workflow_actions_are_pinned_and_checkout_drops_credentials() -> None:
    """A mutable action ref or checkout credential retention violates CI policy."""
    workflow_dir = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    workflows = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    assert workflows, "Expected workflow files to enforce the CI supply-chain policy"
    violations: list[str] = []
    for workflow in workflows:
        violations.extend(
            _workflow_violations(
                workflow.read_text(encoding="utf-8"), name=workflow.name
            )
        )
    assert not violations, "\n".join(violations)


def test_workflow_policy_keeps_yaml_boolean_like_job_ids_distinct() -> None:
    """One valid job ID must not overwrite another while enforcing action policy."""
    source = """
jobs:
  on:
    steps:
      - uses: hostile/example@main
  yes:
    steps:
      - uses: ./local-action
"""

    assert _workflow_violations(source, name="collision.yml") == [
        "collision.yml: mutable external action hostile/example@main"
    ]
