"""Auditable summaries of Agent work without hidden reasoning or raw prompts."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|\s)[a-z]:[\\/]")
_POSIX_HOST_ABSOLUTE = re.compile(
    r"(?:^|\s)/(?:home|Users|root|var|etc|opt|private|mnt)/"
)


class ActivityKind(StrEnum):
    STAGE_STARTED = "STAGE_STARTED"
    EVIDENCE_REVIEWED = "EVIDENCE_REVIEWED"
    CONTEXT_REQUESTED = "CONTEXT_REQUESTED"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    DECISION_RECORDED = "DECISION_RECORDED"
    STAGE_COMPLETED = "STAGE_COMPLETED"
    STAGE_BLOCKED = "STAGE_BLOCKED"
    STAGE_FAILED = "STAGE_FAILED"


class AgentActivityEvent(ContractModel):
    event_id: str = Field(min_length=1, max_length=256)
    analysis_id: str = Field(min_length=1, max_length=128)
    workspace_id: str = Field(min_length=1, max_length=256)
    commit_id: str = Field(min_length=1, max_length=256)
    hypothesis_id: str | None = None
    stage: str = Field(min_length=1, max_length=128)
    agent_role: str = Field(min_length=1, max_length=128)
    attempt_id: str = Field(min_length=1, max_length=256)
    sequence: int = Field(ge=1)
    kind: ActivityKind
    status: str = Field(min_length=1, max_length=64)
    summary_ko: str = Field(min_length=1, max_length=4000)
    input_refs: tuple[StoredDataRef, ...] = ()
    output_refs: tuple[StoredDataRef, ...] = ()
    tool_name: str | None = None
    tool_result_refs: tuple[StoredDataRef, ...] = ()
    provider: str | None = None
    model: str | None = None
    prompt_digest: str | None = None
    output_digest: str | None = None
    error_code: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    elapsed_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_public_event(self) -> AgentActivityEvent:
        for digest in (self.prompt_digest, self.output_digest):
            if digest is not None and _DIGEST.fullmatch(digest) is None:
                raise ValueError("AGENT_ACTIVITY_DIGEST_INVALID")
        for ref in (*self.input_refs, *self.output_refs, *self.tool_result_refs):
            if (
                str(ref.workspace_id) != self.workspace_id
                or str(ref.commit_id) != self.commit_id
            ):
                raise ValueError("AGENT_ACTIVITY_REFERENCE_SCOPE_MISMATCH")
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("AGENT_ACTIVITY_TIME_INVALID")
        public_values = tuple(
            value
            for value in (
                self.stage,
                self.agent_role,
                self.status,
                self.summary_ko,
                self.tool_name,
                self.provider,
                self.model,
                self.error_code,
            )
            if value is not None
        )
        try:
            for value in public_values:
                assert_safe_provider_text(value.encode("utf-8"))
                if _WINDOWS_ABSOLUTE.search(value) or _POSIX_HOST_ABSOLUTE.search(
                    value
                ):
                    raise ValueError("host path")
        except ValueError as error:
            raise ValueError("AGENT_ACTIVITY_UNSAFE") from error
        return self


__all__ = ["ActivityKind", "AgentActivityEvent"]
