"""Fail-closed Technical Gate evidence check for reportable consumers."""

from __future__ import annotations

import json

from .artifacts import SimpleArtifactRepository
from .models import SimpleStage, StageCheckpoint, StageStatus


def technical_gate_accepted(
    checkpoint: StageCheckpoint | None, artifacts: SimpleArtifactRepository
) -> bool:
    if (
        checkpoint is None
        or checkpoint.stage is not SimpleStage.TECH_GATE_DONE
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.gate_decision != "ACCEPT"
        or len(checkpoint.output_refs) != 1
    ):
        return False
    value = json.loads(artifacts.read(checkpoint.output_refs[0]))
    if not isinstance(value, dict):
        return False
    result = value.get("result")
    return isinstance(result, dict) and result.get("status") == "ACCEPT"
