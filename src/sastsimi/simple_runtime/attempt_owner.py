"""Small, immutable ownership metadata for one logical LLM operation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttemptOwner:
    analysis_id: str
    stage: str
    candidate_ids: tuple[str, ...] = ()
    hypothesis_id: str | None = None
    surface_id: str | None = None
    file_path: str | None = None
    batch_id: str | None = None
    context_id: str | None = None
    checkpoint_attempt_id: str | None = None

    def __post_init__(self) -> None:
        if not self.analysis_id or not self.stage:
            raise ValueError("LLM_ATTEMPT_OWNER_INVALID")
        if len(set(self.candidate_ids)) != len(self.candidate_ids):
            raise ValueError("LLM_ATTEMPT_OWNER_INVALID")


@dataclass(frozen=True, slots=True)
class PromptByteCounts:
    raw_source_bytes: int | None = None
    shared_context_bytes: int | None = None
    candidate_specific_bytes: int | None = None
    fixed_prompt_bytes: int | None = None

    def __post_init__(self) -> None:
        if any(
            value is not None and (type(value) is not int or value < 0)
            for value in (
                self.raw_source_bytes,
                self.shared_context_bytes,
                self.candidate_specific_bytes,
                self.fixed_prompt_bytes,
            )
        ):
            raise ValueError("LLM_PROMPT_BYTES_INVALID")
