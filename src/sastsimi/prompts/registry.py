"""Immutable prompt definitions and exact active-entry selection."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr, SchemaVersion, Sha256
from sastsimi.contracts.llm import LLMRole, PromptRegistryEntry, Purpose

REQUIRED_TEMPLATE_SECTIONS = (
    "ROLE_AND_SCOPE",
    "TASK",
    "TRUSTED_RULES",
    "INPUT_SLOTS",
    "UNTRUSTED_DATA_BOUNDARY",
    "DECISION_CRITERIA",
    "OUTPUT_SCHEMA",
    "UNCERTAINTY_AND_ERRORS",
    "FORBIDDEN_BEHAVIOR",
)


class PromptManifestItem(ContractModel):
    template_path: NonEmptyStr
    template_sha256: Sha256
    entry: PromptRegistryEntry

    @model_validator(mode="after")
    def exact_template_reference(self) -> Self:
        ref = self.entry.template_ref
        if (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != self.template_sha256
            or ref.content_hash != self.template_sha256
        ):
            raise ValueError("PROMPT_TEMPLATE_REFERENCE_MISMATCH")
        return self


class PromptManifest(ContractModel):
    manifest_version: SchemaVersion
    kind: Literal["SASTSIMI_PROMPT_FIXTURE"]
    entries: tuple[PromptManifestItem, ...]

    @model_validator(mode="after")
    def nonempty_manifest(self) -> Self:
        if not self.entries:
            raise ValueError("PROMPT_REGISTRY_EMPTY")
        return self


@dataclass(frozen=True)
class LoadedPromptDefinition:
    entry: PromptRegistryEntry
    template_path: Path
    template: bytes
    template_sha256: str

    @classmethod
    def from_bytes(
        cls,
        *,
        entry: PromptRegistryEntry,
        template_path: Path,
        template: bytes,
        expected_sha256: str | None = None,
    ) -> Self:
        digest = hashlib.sha256(template).hexdigest()
        expected = expected_sha256 or entry.template_ref.content_hash
        if digest != expected or entry.template_ref.content_hash != digest:
            raise ValueError("PROMPT_TEMPLATE_HASH_MISMATCH")
        try:
            text = template.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("PROMPT_TEMPLATE_ENCODING_INVALID") from error
        missing = tuple(
            section
            for section in REQUIRED_TEMPLATE_SECTIONS
            if f"# {section}" not in text
        )
        if missing:
            raise ValueError("PROMPT_TEMPLATE_SECTION_MISSING: " + ",".join(missing))
        return cls(entry, template_path, template, digest)


class PromptRegistry:
    def __init__(self, definitions: tuple[LoadedPromptDefinition, ...]) -> None:
        active: set[tuple[str, str, str]] = set()
        for definition in definitions:
            entry = definition.entry
            if entry.status != "ACTIVE":
                continue
            key = (entry.agent_role, entry.task_kind, entry.purpose)
            if key in active:
                raise ValueError("PROMPT_REGISTRY_ACTIVE_DUPLICATE")
            active.add(key)
        self._definitions = definitions

    @property
    def definitions(self) -> tuple[LoadedPromptDefinition, ...]:
        return self._definitions

    def select(
        self, agent_role: LLMRole, task_kind: str, purpose: Purpose
    ) -> LoadedPromptDefinition:
        matches = tuple(
            definition
            for definition in self._definitions
            if definition.entry.status == "ACTIVE"
            and definition.entry.agent_role == agent_role
            and definition.entry.task_kind == task_kind
            and definition.entry.purpose == purpose
        )
        if len(matches) != 1:
            raise LookupError("PROMPT_REGISTRY_NOT_ACTIVE")
        return matches[0]
