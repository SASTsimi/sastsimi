from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity


def _repository(tmp_path: Path) -> SimpleArtifactRepository:
    return SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="commit-1",
            hypothesis_id="hypothesis-1",
        ),
    )


def test_strict_context_keeps_policy_exact_and_redacts_complete_optional_inputs(
    tmp_path: Path,
) -> None:
    artifacts = _repository(tmp_path)
    policy = "# Policy\nProduction only.\n\n> Approved scope.\n"
    policy_ref = artifacts.put_bytes(policy.encode(), "text/markdown")
    technical_ref = artifacts.put_json(
        {"kind": "technical", "result": {"status": "ACCEPT", "api_key": "tech-secret"}}
    )
    poc_ref = artifacts.put_bytes(b"log: Bearer poc-secret-123\n", "text/plain")
    verification_ref = artifacts.put_json(
        {"kind": "verification", "result": {"status": "TRUE", "token": "verify-secret"}}
    )

    context = artifacts.prompt_context_strict(
        (policy_ref, technical_ref, poc_ref, verification_ref)
    )
    inputs = json.loads(context)["exact_inputs"]

    assert [item["data"] for item in inputs] == [
        policy,
        {
            "kind": "technical",
            "result": {"status": "ACCEPT", "api_key": "[REDACTED:CREDENTIAL]"},
        },
        "log: [REDACTED:TOKEN]\n",
        {
            "kind": "verification",
            "result": {"status": "TRUE", "token": "[REDACTED:CREDENTIAL]"},
        },
    ]
    assert b"tech-secret" not in context
    assert b"poc-secret" not in context
    assert b"verify-secret" not in context


def test_strict_context_budgets_redacted_optional_data(tmp_path: Path) -> None:
    artifacts = _repository(tmp_path)
    policy_ref = artifacts.put_bytes(b"# Scope\nProduction only.\n", "text/markdown")
    technical_ref = artifacts.put_json({"api_key": "x" * (300 * 1024)})

    context = artifacts.prompt_context_strict((policy_ref, technical_ref))

    assert json.loads(context)["exact_inputs"][1]["data"] == {
        "api_key": "[REDACTED:CREDENTIAL]"
    }
    assert len(context) <= 256 * 1024


def test_strict_context_rejects_large_redacted_input_without_truncation(
    tmp_path: Path,
) -> None:
    artifacts = _repository(tmp_path)
    policy_ref = artifacts.put_bytes(b"# Scope\nProduction only.\n", "text/markdown")
    technical_ref = artifacts.put_json({"status": "x" * (300 * 1024)})

    with pytest.raises(ValueError, match="SIMPLE_RUNTIME_CONTEXT_TOO_LARGE"):
        artifacts.prompt_context_strict((policy_ref, technical_ref))
