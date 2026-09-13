"""Reject mutable external workflow actions and retained checkout credentials."""

from __future__ import annotations

import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]


def test_workflow_actions_are_pinned_and_checkout_drops_credentials() -> None:
    """A mutable action ref or checkout credential retention violates CI policy."""
    workflow_dir = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    workflows = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    assert workflows, "Expected workflow files to enforce the CI supply-chain policy"
    violations: list[str] = []
    for workflow in workflows:
        pending: list[object] = [yaml.safe_load(workflow.read_text(encoding="utf-8"))]
        while pending:
            node = pending.pop()
            if isinstance(node, list):
                pending.extend(node)
            elif isinstance(node, dict):
                pending.extend(node.values())
                if "uses" not in node:
                    continue
                uses = node["uses"]
                assert isinstance(uses, str), f"{workflow.name}: invalid uses value"
                if uses.startswith("./"):
                    continue
                action, separator, revision = uses.partition("@")
                if not separator or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                    violations.append(
                        f"{workflow.name}: mutable external action {uses}"
                    )
                if action.lower() == "actions/checkout":
                    options = node.get("with", {})
                    if (
                        not isinstance(options, dict)
                        or options.get("persist-credentials") is not False
                    ):
                        violations.append(
                            f"{workflow.name}: {uses} "
                            "must set persist-credentials: false"
                        )
    assert not violations, "\n".join(violations)
