"""Strictly parse pinned v1/v2 recall oracle JSON bytes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sastsimi.simple_runtime.recall_audit import Oracle, OracleCase


class _CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    case_id: str = Field(min_length=1)
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    path: str = Field(min_length=1)
    source_line: int | None = Field(ge=1)
    sink_line: int = Field(ge=1)
    rationale: str = Field(min_length=1)
    vetted_candidate_ids: tuple[str, ...] = ()
    vetted_hypothesis_ids: tuple[str, ...] = ()
    finding_inventory_reviewed: bool = False
    kind: Literal["FLOW", "MISSING_GUARD", "CONFIGURATION"] = "FLOW"
    sink_path: str | None = None
    scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON"


class _OracleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    repository: str = Field(min_length=1)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    cases: tuple[_CaseInput, ...] = Field(min_length=1)
    version: Literal[1, 2] = 1
    completeness: Literal["UNDECLARED", "DOCUMENTED_CASES", "EXHAUSTIVE_PYTHON"] = (
        "UNDECLARED"
    )

    @model_validator(mode="after")
    def unique_case_ids(self) -> _OracleInput:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("duplicate oracle case ID")
        if self.version == 2:
            for case in self.cases:
                if (
                    case.vetted_candidate_ids
                    or case.vetted_hypothesis_ids
                    or case.finding_inventory_reviewed
                ):
                    raise ValueError("v2 oracle must be frozen before review")
                for path in (case.path, case.sink_path):
                    if path is None:
                        continue
                    if (
                        path.startswith("/")
                        or "\\" in path
                        or ":" in path
                        or any(part in {"", ".", ".."} for part in path.split("/"))
                    ):
                        raise ValueError("unsafe oracle source path")
        return self


def parse_oracle_bytes(payload: bytes) -> Oracle:
    """Validate an external oracle and return its immutable scoring model."""

    parsed = _OracleInput.model_validate_json(payload)
    return Oracle(
        repository=parsed.repository,
        commit=parsed.commit,
        cases=tuple(
            OracleCase(
                case_id=case.case_id,
                cwe=case.cwe,
                path=case.path,
                source_line=case.source_line,
                sink_line=case.sink_line,
                rationale=case.rationale,
                vetted_candidate_ids=case.vetted_candidate_ids,
                vetted_hypothesis_ids=case.vetted_hypothesis_ids,
                finding_inventory_reviewed=case.finding_inventory_reviewed,
                kind=case.kind,
                sink_path=case.sink_path,
                scope=case.scope,
            )
            for case in parsed.cases
        ),
        version=parsed.version,
        completeness=parsed.completeness,
    )
