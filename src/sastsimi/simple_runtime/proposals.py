"""Register hypothesis proposals one at a time, as the design lays out.

``03-agent-roles-and-orchestration.md`` and ``08-lightweight-data-contracts.md``:

    PROPOSED -> schema and semantic validation
        failure -> INVALID_OUTPUT (after a bounded repair)
        success -> runtime narrows duplicate candidates among registered ones
            none -> register (NO_CANDIDATES), no model call
            some -> LLM duplicate review of this proposal against them
                UNIQUE | UNCERTAIN -> register
                DUPLICATE naming a candidate -> not registered
                call or format failure -> register fail-open (CHECK_FAILED)
                a target outside the candidates -> register (INVALID_DUPLICATE_TARGET)

Each proposal is judged on its own, so one malformed proposal costs itself and
not the batch it arrived in, and every outcome is recorded with its reason.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes

from .models import StageFailure
from .provider import SimpleLLMCallResult, SimpleLLMClient

_LOCATION: dict[str, Any] = {
    "type": "object",
    "properties": {
        "file_path": {"type": "string"},
        "start_line": {"type": "integer"},
        "end_line": {"type": "integer"},
    },
}

# What the agent fills in.  ``required`` is kept to the container on purpose:
# a structured-output schema is enforced per call, so requiring every field
# there would fail a whole batch for one incomplete proposal.  The fields are
# required here, per proposal, by ``validate_proposal``.
PROPOSAL_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "statement": {"type": "string"},
        "vulnerability_type_candidates": {
            "type": "array",
            "items": {"type": "string"},
        },
        "target_locations": {"type": "array", "items": _LOCATION},
        "suspected_path": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    **_LOCATION["properties"],
                    "role": {"type": "string"},
                },
            },
        },
        "observed_facts": {"type": "array", "items": {"type": "string"}},
        "restrictions": {"type": "array", "items": {"type": "string"}},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "falsification_questions": {"type": "array", "items": {"type": "string"}},
        "validation_checks": {"type": "array", "items": {"type": "string"}},
    },
}

PROPOSAL_INSTRUCTIONS = (
    "Each hypothesis states one claim in `statement` and never asserts it is "
    "confirmed. Give `vulnerability_type_candidates`, `target_locations` and the "
    "`suspected_path` from source to sink, every location as a repository file "
    "path with the real line numbers shown in the code; separate "
    "`observed_facts` (what the code shows), `restrictions` (checks or "
    "boundaries that limit the attack) and `assumptions` (what must hold but "
    "is not shown); and add at least one `falsification_questions` entry that "
    "real evidence could answer and one `validation_checks` entry that says "
    "what must be confirmed."
)


@dataclass(frozen=True, slots=True)
class Location:
    file_path: str
    start_line: int
    end_line: int

    def overlaps(self, other: Location) -> bool:
        return (
            self.file_path == other.file_path
            and self.start_line <= other.end_line
            and other.start_line <= self.end_line
        )

    def as_text(self) -> str:
        return f"{self.file_path}:{self.start_line}"


def _location(value: object, lines: Mapping[str, int]) -> Location | str:
    if not isinstance(value, dict):
        return "location is not an object"
    path = value.get("file_path")
    start = value.get("start_line")
    end = value.get("end_line", start)
    if not isinstance(path, str) or not path.strip():
        return "location has no file_path"
    # ``removeprefix``, not ``lstrip``: stripping the characters ``./`` would
    # turn ``.github/x`` into ``github/x``.
    path = path.strip().removeprefix("./").lstrip("/")
    if path not in lines:
        return f"{path} is not a file in the checkout"
    if not isinstance(start, int) or isinstance(start, bool):
        return f"{path} has no start_line"
    if not isinstance(end, int) or isinstance(end, bool):
        end = start
    if start < 1 or end < start or end > lines[path]:
        return f"{path}:{start}-{end} is outside the file's {lines[path]} lines"
    return Location(path, start, end)


def _strings(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def validate_proposal(
    value: object, *, lines: Mapping[str, int]
) -> tuple[dict[str, Any] | None, list[str]]:
    """Return the normalised proposal, or ``None`` and why it is not valid.

    ``lines`` maps every checkout file a proposal may name to its line count,
    so a location is checked against the file rather than taken on trust.
    """

    if not isinstance(value, dict):
        return None, ["proposal is not an object"]
    errors: list[str] = []
    statement = value.get("statement")
    if not isinstance(statement, str) or not statement.strip():
        errors.append("statement is missing")
    types = _strings(value.get("vulnerability_type_candidates"))
    if types is None:
        errors.append("vulnerability_type_candidates is missing")
    elif len(set(types)) != len(types):
        errors.append("vulnerability_type_candidates repeats a value")
    targets: list[Location] = []
    raw_targets = value.get("target_locations")
    if not isinstance(raw_targets, list) or not raw_targets:
        errors.append("target_locations is missing")
    else:
        for item in raw_targets:
            parsed = _location(item, lines)
            if isinstance(parsed, str):
                errors.append(f"target_locations: {parsed}")
            else:
                targets.append(parsed)
    path: list[dict[str, Any]] = []
    raw_path = value.get("suspected_path")
    if not isinstance(raw_path, list) or not raw_path:
        errors.append("suspected_path is missing")
    else:
        for item in raw_path:
            parsed = _location(item, lines)
            if isinstance(parsed, str):
                errors.append(f"suspected_path: {parsed}")
            else:
                role = item.get("role") if isinstance(item, dict) else None
                path.append(
                    {
                        "file_path": parsed.file_path,
                        "start_line": parsed.start_line,
                        "end_line": parsed.end_line,
                        "role": role if isinstance(role, str) else "",
                    }
                )
    lists: dict[str, list[str]] = {}
    for key in ("observed_facts", "restrictions", "assumptions"):
        found = _strings(value.get(key))
        if found is None:
            errors.append(f"{key} is missing")
        lists[key] = found or []
    questions = _strings(value.get("falsification_questions"))
    if not questions:
        errors.append("falsification_questions needs at least one question")
    checks = _strings(value.get("validation_checks"))
    if not checks:
        errors.append("validation_checks needs at least one check")
    if errors:
        return None, errors
    assert isinstance(statement, str) and types is not None
    assert questions is not None and checks is not None
    return (
        {
            "proposal_state": "HYPOTHESIS_ONLY",
            "assertion_mode": "NON_FINAL",
            "origin": "INITIAL",
            "statement": statement.strip(),
            "vulnerability_type_candidates": types,
            "target_locations": [
                {
                    "file_path": item.file_path,
                    "start_line": item.start_line,
                    "end_line": item.end_line,
                }
                for item in targets
            ],
            "suspected_path": path,
            **lists,
            # IDs are the runtime's to assign, so a repeated or missing one
            # cannot come from the model.
            "falsification_questions": [
                {"question_id": f"Q{index}", "question": question}
                for index, question in enumerate(questions, start=1)
            ],
            "validation_checks": [
                {"validation_id": f"V{index}", "instruction": check}
                for index, check in enumerate(checks, start=1)
            ],
            "parent_hypothesis_ids": [],
            "source_primitive_match_id": None,
            # Read by the reproduction environment, which locates a target's
            # own manifest from these.
            "code_locations": [item.as_text() for item in targets],
        },
        [],
    )


def locations_of(proposal: Mapping[str, Any]) -> list[Location]:
    found: list[Location] = []
    for key in ("target_locations", "suspected_path"):
        for item in proposal.get(key, ()):
            if isinstance(item, dict):
                found.append(
                    Location(
                        str(item["file_path"]),
                        int(item["start_line"]),
                        int(item["end_line"]),
                    )
                )
    return found


@dataclass
class Registered:
    hypothesis_id: str
    proposal: dict[str, Any]
    locations: list[Location]


@dataclass
class Registry:
    """The analysis's registered hypotheses, and what became of every proposal."""

    bundle_hash: str
    registered: list[Registered] = field(default_factory=list)
    states: list[dict[str, Any]] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _hypothesis_id(self, proposal: Mapping[str, Any]) -> str:
        digest = hashlib.sha256(
            self.bundle_hash.encode() + canonical_bytes(dict(proposal))
        ).hexdigest()[:32]
        return f"hypothesis-{digest}"

    def record_invalid(self, proposal_id: str, batch: int, errors: list[str]) -> None:
        self.states.append(
            {
                "proposal_id": proposal_id,
                "batch": batch,
                "status": "INVALID_OUTPUT",
                "errors": errors,
            }
        )

    async def consider(
        self,
        proposal: dict[str, Any],
        *,
        proposal_id: str,
        batch: int,
        client: SimpleLLMClient,
        timeout_ms: int,
    ) -> Registered | None:
        """Register ``proposal`` unless the model names it a duplicate."""

        # One at a time: each proposal is compared with what is registered at
        # that moment, so two batches cannot both register the same defect.
        async with self._lock:
            mine = locations_of(proposal)
            candidates = [
                entry
                for entry in self.registered
                if any(a.overlaps(b) for a in mine for b in entry.locations)
            ]
            state: dict[str, Any] = {
                "proposal_id": proposal_id,
                "batch": batch,
                "candidate_hypothesis_ids": [e.hypothesis_id for e in candidates],
            }
            if not candidates:
                state.update(status="SCHEMA_VALID", reason="NO_CANDIDATES")
                return self._register(proposal, mine, state)
            review = await _duplicate_review(
                client, proposal, candidates, timeout_ms=timeout_ms
            )
            state["review"] = review
            decision = review.get("decision")
            target = review.get("duplicate_of")
            ids = {entry.hypothesis_id for entry in candidates}
            if decision == "DUPLICATE" and target in ids:
                state.update(status="DUPLICATE", duplicate_of=target)
                self.states.append(state)
                return None
            if decision == "DUPLICATE":
                reason = "INVALID_DUPLICATE_TARGET"
            elif decision in ("UNIQUE", "UNCERTAIN"):
                reason = str(decision)
            else:
                reason = "CHECK_FAILED"
            state.update(status="SCHEMA_VALID", reason=reason)
            return self._register(proposal, mine, state)

    def _register(
        self,
        proposal: dict[str, Any],
        locations: list[Location],
        state: dict[str, Any],
    ) -> Registered:
        entry = Registered(self._hypothesis_id(proposal), proposal, locations)
        state["hypothesis_id"] = entry.hypothesis_id
        self.registered.append(entry)
        self.states.append(state)
        return entry

    def record(self) -> dict[str, Any]:
        statuses: dict[str, int] = {}
        for state in self.states:
            key = str(state.get("reason") or state["status"])
            statuses[key] = statuses.get(key, 0) + 1
        return {
            "kind": "simple_proposal_process_states",
            "registered": len(self.registered),
            "outcomes": statuses,
            "states": self.states,
        }


async def _duplicate_review(
    client: SimpleLLMClient,
    proposal: Mapping[str, Any],
    candidates: list[Registered],
    *,
    timeout_ms: int,
) -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "decision": {"enum": ["UNIQUE", "DUPLICATE", "UNCERTAIN"]},
            "duplicate_of": {"type": ["string", "null"]},
            "rationale": {"type": "string"},
        },
        "required": ["decision", "duplicate_of", "rationale"],
        "additionalProperties": False,
    }
    prompt = (
        b"You are the Hypothesis Agent reviewing one new proposal against the "
        b"registered hypotheses whose code locations overlap it. It is a "
        b"DUPLICATE only when it describes the same defect as one of them - the "
        b"same source reaching the same sink through the same flow - and then "
        b"`duplicate_of` names that hypothesis_id. A different endpoint, sink, "
        b"precondition or impact is UNIQUE. When unsure, answer UNCERTAIN.\n"
        b"<UNTRUSTED_EXACT_INPUTS>\n"
        + canonical_bytes(
            {
                "proposal": dict(proposal),
                "registered": [
                    {"hypothesis_id": e.hypothesis_id, "proposal": e.proposal}
                    for e in candidates
                ],
            }
        )
        + b"\n</UNTRUSTED_EXACT_INPUTS>\n"
    )
    answer = await client.call(
        prompt=prompt, output_schema=schema, timeout_ms=timeout_ms
    )
    if isinstance(answer, StageFailure) or not isinstance(answer, SimpleLLMCallResult):
        code = answer.code if isinstance(answer, StageFailure) else "FAILED"
        return {"decision": None, "error": code}
    return dict(answer.value)


__all__ = [
    "PROPOSAL_INSTRUCTIONS",
    "PROPOSAL_ITEM_SCHEMA",
    "Location",
    "Registered",
    "Registry",
    "locations_of",
    "validate_proposal",
]
