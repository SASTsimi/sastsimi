"""Shared CLI/dashboard progress calculation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Literal, Protocol

from sastsimi.simple_runtime.attack_surfaces import SurfaceIndex
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CandidateTerminal,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    terminal_gate_outcome,
    terminal_poc_outcome,
)

from .models import ProgressSnapshot

_ANALYSIS_STAGES = (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE)
_CANDIDATE_DECISIONS = ("PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR")
_DEEP_STATUSES = (
    "PENDING",
    "RUNNING",
    "COMPLETE",
    "NO_HYPOTHESIS",
    "INCONCLUSIVE",
    "ERROR",
)
_SURFACE_STATUSES = ("COVERED", "UNCOVERED", "INSUFFICIENT")
_BUDGET_CODES = frozenset(
    {
        "LLM_TOKEN_BUDGET_EXHAUSTED",
        "LLM_COST_BUDGET_EXHAUSTED",
        "LLM_ELAPSED_BUDGET_EXHAUSTED",
        "LLM_TOKEN_USAGE_UNAVAILABLE",
        "LLM_COST_USAGE_UNAVAILABLE",
    }
)
_CHILD_ERROR_PREFIX = "CANDIDATE_CHILD_ERROR:"
_BOUND_CHILD_ERROR_PREFIX = "CANDIDATE_CHILD_ERROR_BOUND:"


def _visible_child_error(
    checkpoints: list[StageCheckpoint], selected: StageCheckpoint
) -> StageCheckpoint:
    if (
        selected.stage is not SimpleStage.HYPOTHESIS_DONE
        or selected.identity.hypothesis_id is not None
        or selected.error_code is None
    ):
        return selected
    child_id = ""
    attempt_id = ""
    if selected.error_code.startswith("CANDIDATE_CHILD_CODEX_STATE_PENDING"):
        parts = selected.error_code.split(":", 2)
        if len(parts) == 3:
            child_id, attempt_id = parts[1:]
        codes = {"CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"}
    elif selected.error_code.startswith(_BOUND_CHILD_ERROR_PREFIX):
        payload = selected.error_code.removeprefix(_BOUND_CHILD_ERROR_PREFIX)
        parts = payload.rsplit(":", 2)
        codes = {parts[0] if len(parts) == 3 else payload}
        if len(parts) == 3:
            child_id, attempt_id = parts[1:]
    elif selected.error_code.startswith(_CHILD_ERROR_PREFIX):
        codes = {selected.error_code.removeprefix(_CHILD_ERROR_PREFIX)}
    else:
        return selected
    children = [
        item
        for item in checkpoints
        if item.identity.hypothesis_id is not None
        and child_id != ""
        and attempt_id != ""
        and item.identity.hypothesis_id == child_id
        and item.attempt_id == attempt_id
        and item.identity.analysis_id == selected.identity.analysis_id
        and item.identity.workspace_id == selected.identity.workspace_id
        and item.identity.commit_id == selected.identity.commit_id
        and item.error_code in codes
    ]
    if children:
        return max(children, key=lambda item: item.updated_at)
    if selected.error_code.startswith("CANDIDATE_CHILD_CODEX_STATE_PENDING"):
        return selected.model_copy(
            update={"error_code": "CODEX_PROCESS_CLEANUP_UNCONFIRMED"}
        )
    if selected.error_code.startswith((_CHILD_ERROR_PREFIX, _BOUND_CHILD_ERROR_PREFIX)):
        return selected.model_copy(update={"error_code": next(iter(codes))})
    return selected


def _normalized_counts(
    counts: Mapping[str, int] | None, statuses: tuple[str, ...]
) -> dict[str, int]:
    if counts is None:
        return {status: 0 for status in statuses}
    if any(
        status not in statuses or type(value) is not int or value < 0
        for status, value in counts.items()
    ):
        raise ValueError("ANALYSIS_PROGRESS_CANDIDATE_COUNTS_INVALID")
    return {status: counts.get(status, 0) for status in statuses}


def verified_surface_coverage_counts(
    payload: object, index: SurfaceIndex, terminal: CandidateTerminal
) -> dict[str, int] | None:
    """Count only a scope-bound coverage artifact that agrees with terminal proof."""

    if not isinstance(payload, dict):
        return None
    if (
        payload.get("kind") != "simple_attack_surface_coverage_v1"
        or payload.get("scope_fingerprint") != index.scope_fingerprint
        or payload.get("static_bundle_hash") != index.static_bundle_hash
        or payload.get("ast_manifest_hash") != index.ast_manifest_hash
        or payload.get("candidate_inventory_hash") != index.candidate_inventory_hash
        or payload.get("candidate_count") != index.candidate_count
        or payload.get("static_gaps") != index.to_json()["static_gaps"]
    ):
        return None
    rows = payload.get("surfaces")
    if not isinstance(rows, list):
        return None
    indexed_ids = {surface.surface_id for surface in index.surfaces}
    seen: set[str] = set()
    counts = {status: 0 for status in _SURFACE_STATUSES}
    for row in rows:
        if not isinstance(row, dict):
            return None
        surface_id = row.get("surface_id")
        status = row.get("coverage_status")
        if (
            not isinstance(surface_id, str)
            or surface_id not in indexed_ids
            or surface_id in seen
            or not isinstance(status, str)
            or status not in counts
        ):
            return None
        seen.add(surface_id)
        counts[status] += 1
    complete = not index.static_gaps and counts["COVERED"] == len(indexed_ids)
    if (
        seen != indexed_ids
        or payload.get("complete") is not complete
        or counts != terminal.surface_counts
        or terminal.status == "COMPLETE"
        and not complete
    ):
        return None
    return counts


class CheckpointQuery(Protocol):
    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]: ...


class ProgressProjector:
    def __init__(self, store: CheckpointQuery) -> None:
        self._store = store

    def snapshot(
        self,
        analysis_id: str,
        *,
        static_disposition: Literal["FULL", "PARTIAL"] = "FULL",
        candidate_pipeline_version: int = 0,
        candidate_counts: Mapping[str, int] | None = None,
        candidate_deep_counts: Mapping[str, int] | None = None,
        registered_hypothesis_count: int | None = None,
        candidate_terminal: CandidateTerminal | None = None,
        candidate_bundle_hash: str | None = None,
        candidate_scope_fingerprint: str | None = None,
        surface_counts: Mapping[str, int] | None = None,
        surface_index_hash: str | None = None,
    ) -> ProgressSnapshot:
        checkpoints = self._store.list_checkpoints(analysis_id)
        if not checkpoints:
            raise LookupError("ANALYSIS_PROGRESS_NOT_FOUND")
        by_hypothesis: dict[str, list[StageCheckpoint]] = defaultdict(list)
        analysis_level: list[StageCheckpoint] = []
        for checkpoint in checkpoints:
            hypothesis_id = checkpoint.identity.hypothesis_id
            if hypothesis_id is None:
                analysis_level.append(checkpoint)
            else:
                by_hypothesis[hypothesis_id].append(checkpoint)

        completed = sum(item.status is StageStatus.SUCCEEDED for item in analysis_level)
        known = len(_ANALYSIS_STAGES) if analysis_level else 0
        skipped = 0
        terminal_hypotheses = 0
        inconclusive_hypotheses = 0
        rejected_hypotheses = 0
        for values in by_hypothesis.values():
            known += len(HYPOTHESIS_STAGES)
            completed += sum(item.status is StageStatus.SUCCEEDED for item in values)
            final = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.VERIFICATION_FINAL_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            chain = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.CHAINING_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            execution = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.POC_EXECUTION_DONE
                ),
                None,
            )
            report = next(
                (
                    item
                    for item in values
                    if item.stage is SimpleStage.REPORT_DONE
                    and item.status is StageStatus.SUCCEEDED
                ),
                None,
            )
            gate = next(
                (item for item in values if item.stage is SimpleStage.TECH_GATE_DONE),
                None,
            )
            gate_outcome = terminal_gate_outcome(gate)
            if terminal_poc_outcome(execution) is not None:
                execution_index = HYPOTHESIS_STAGES.index(
                    SimpleStage.POC_EXECUTION_DONE
                )
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[execution_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[execution_index + 1 :]) - present_after
                terminal_hypotheses += 1
                inconclusive_hypotheses += 1
            elif final is not None and (
                final.verdict == "FALSE"
                or final.verdict == "HOLD"
                and chain is not None
            ):
                final_index = HYPOTHESIS_STAGES.index(
                    SimpleStage.VERIFICATION_FINAL_DONE
                )
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[final_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[final_index + 1 :]) - present_after
                terminal_hypotheses += 1
            elif gate_outcome is not None:
                gate_index = HYPOTHESIS_STAGES.index(SimpleStage.TECH_GATE_DONE)
                present_after = sum(
                    item.stage in HYPOTHESIS_STAGES[gate_index + 1 :]
                    and item.status is StageStatus.SUCCEEDED
                    for item in values
                )
                skipped += len(HYPOTHESIS_STAGES[gate_index + 1 :]) - present_after
                terminal_hypotheses += 1
                if gate_outcome == "REJECT":
                    rejected_hypotheses += 1
                else:
                    inconclusive_hypotheses += 1
            elif report is not None:
                terminal_hypotheses += 1

        registered_hypotheses = max(
            len(by_hypothesis), registered_hypothesis_count or 0
        )
        known += (registered_hypotheses - len(by_hypothesis)) * len(HYPOTHESIS_STAGES)
        candidate_mode = candidate_pipeline_version >= 1
        decisions = (
            _normalized_counts(candidate_counts, _CANDIDATE_DECISIONS)
            if candidate_mode and candidate_counts is not None
            else {}
        )
        deep = (
            _normalized_counts(candidate_deep_counts, _DEEP_STATUSES)
            if candidate_mode and candidate_counts is not None
            else {}
        )
        candidate_total = sum(decisions.values())
        deep_eligible = decisions.get("INCLUDE", 0) + decisions.get("UNDECIDED", 0)
        deep_completed = (
            deep.get("COMPLETE", 0)
            + deep.get("NO_HYPOTHESIS", 0)
            + deep.get("INCONCLUSIVE", 0)
        )
        terminal_valid = bool(
            candidate_mode
            and candidate_counts is not None
            and candidate_terminal is not None
            and candidate_bundle_hash is not None
            and candidate_scope_fingerprint is not None
            and (
                candidate_pipeline_version >= 2
                or candidate_terminal.status
                == ("PARTIAL" if static_disposition == "PARTIAL" else "COMPLETE")
            )
            and candidate_terminal.bundle_hash == candidate_bundle_hash
            and candidate_terminal.scope_fingerprint == candidate_scope_fingerprint
            and _normalized_counts(
                candidate_terminal.decision_counts, _CANDIDATE_DECISIONS
            )
            == decisions
            and _normalized_counts(candidate_terminal.deep_counts, _DEEP_STATUSES)
            == deep
            and candidate_terminal.hypothesis_count == registered_hypotheses
        )
        surface_phase: dict[str, int] | None = None
        if candidate_pipeline_version >= 2 and surface_counts is not None:
            if any(
                key not in {*_SURFACE_STATUSES, "CONTEXT_RECORDS", "TOTAL"}
                or type(value) is not int
                or value < 0
                for key, value in surface_counts.items()
            ):
                raise ValueError("ANALYSIS_PROGRESS_SURFACE_COUNTS_INVALID")
            total = surface_counts.get("TOTAL", 0)
            recorded_contexts = surface_counts.get("CONTEXT_RECORDS", 0)
            surface_phase = {
                "recorded_contexts": recorded_contexts,
                "completed": 0,
                "total": total,
            }
            known += total
        if candidate_pipeline_version >= 2:
            producer_output_hashes = {
                ref.content_hash
                for checkpoint in analysis_level
                if checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
                and checkpoint.status is StageStatus.SUCCEEDED
                for ref in checkpoint.output_refs
            }
            terminal_surface_counts = (
                getattr(candidate_terminal, "surface_counts", {})
                if candidate_terminal is not None
                else {}
            )
            terminal_surface_total = sum(
                terminal_surface_counts.get(status, 0) for status in _SURFACE_STATUSES
            )
            terminal_valid = bool(
                terminal_valid
                and candidate_terminal is not None
                and surface_phase is not None
                and surface_counts is not None
                and surface_index_hash
                and getattr(candidate_terminal, "surface_index_hash", None)
                == surface_index_hash
                and getattr(candidate_terminal, "surface_coverage_hash", None)
                in producer_output_hashes
                and surface_index_hash in producer_output_hashes
                and getattr(candidate_terminal, "producer_finished", False)
                and getattr(candidate_terminal, "pending_child_count", -1) == 0
                and terminal_surface_total == surface_phase["total"]
                and all(
                    surface_counts.get(status) == terminal_surface_counts.get(status, 0)
                    for status in _SURFACE_STATUSES
                )
                and (
                    candidate_terminal.status != "COMPLETE"
                    or (
                        static_disposition == "FULL"
                        and terminal_surface_counts.get("UNCOVERED", 0) == 0
                        and terminal_surface_counts.get("INSUFFICIENT", 0) == 0
                    )
                )
            )
            if terminal_valid and surface_phase is not None:
                covered = terminal_surface_counts.get("COVERED", 0)
                completed += covered
                surface_phase.update(
                    {
                        "completed": covered,
                        "covered": covered,
                        "uncovered": terminal_surface_counts.get("UNCOVERED", 0),
                        "insufficient": terminal_surface_counts.get("INSUFFICIENT", 0),
                    }
                )
        if candidate_mode and candidate_counts is not None:
            known += candidate_total + deep_eligible
            completed += (
                decisions["INCLUDE"]
                + decisions["EXCLUDE"]
                + decisions["UNDECIDED"]
                + min(deep_completed, deep_eligible)
            )
        finding_count = sum(
            item.stage is SimpleStage.FINDING_DONE
            and item.status is StageStatus.SUCCEEDED
            and item.verdict == "TRUE"
            and bool(item.output_refs)
            for item in checkpoints
        )
        status, current = self._status(
            checkpoints,
            terminal_hypotheses,
            registered_hypotheses,
            static_disposition=static_disposition,
            candidate_pipeline_version=candidate_pipeline_version,
            candidate_counts=decisions if candidate_counts is not None else None,
            candidate_deep_counts=deep,
            candidate_terminal_valid=terminal_valid,
            candidate_terminal_status=(
                candidate_terminal.status
                if terminal_valid and candidate_terminal
                else None
            ),
        )
        credited = completed + skipped
        percent = (
            100
            if status == "COMPLETE"
            else min(99, int(credited * 100 / max(known, 1)))
        )
        error_code = current.error_code
        if status == "BLOCKED" and error_code is None:
            if decisions.get("ERROR", 0):
                error_code = "CANDIDATE_DISCOVERY_ERROR"
            elif deep.get("ERROR", 0):
                error_code = "CANDIDATE_DEEP_ERROR"
        return ProgressSnapshot(
            analysis_id=analysis_id,
            status=status,
            completed_units=completed,
            skipped_units=skipped,
            known_units=known,
            percent=percent,
            percentage_kind=(
                "known_checkpoint_fraction" if candidate_pipeline_version >= 2 else None
            ),
            phase_counts=(
                {
                    "static": {
                        "completed": sum(
                            item.stage is SimpleStage.STATIC_DONE
                            and item.status is StageStatus.SUCCEEDED
                            for item in analysis_level
                        ),
                        "known": 1,
                    },
                    "triage": {
                        "completed": sum(
                            decisions[status]
                            for status in ("INCLUDE", "EXCLUDE", "UNDECIDED")
                        ),
                        "known": candidate_total,
                    },
                    "candidate_deep": {
                        "completed": min(deep_completed, deep_eligible),
                        "known": deep_eligible,
                    },
                    "verification": {
                        "completed": terminal_hypotheses,
                        "known": registered_hypotheses,
                    },
                    "poc": {
                        "attempted": sum(
                            any(
                                item.stage is SimpleStage.POC_EXECUTION_DONE
                                and item.status is not StageStatus.PENDING
                                for item in values
                            )
                            for values in by_hypothesis.values()
                        ),
                        "completed": sum(
                            any(
                                item.stage is SimpleStage.POC_EXECUTION_DONE
                                and item.status is StageStatus.SUCCEEDED
                                for item in values
                            )
                            for values in by_hypothesis.values()
                        ),
                    },
                    **({"surface": surface_phase} if surface_phase is not None else {}),
                }
                if candidate_pipeline_version >= 2 and candidate_counts is not None
                else {}
            ),
            current_stage=current.stage.value,
            current_hypothesis_id=current.identity.hypothesis_id,
            error_code=error_code,
            attempt_number=max(1, current.attempt_number),
            inconclusive_hypothesis_count=inconclusive_hypotheses,
            rejected_hypothesis_count=rejected_hypotheses,
            candidate_total_count=(
                candidate_total
                if candidate_mode and candidate_counts is not None
                else None
            ),
            candidate_decision_counts=decisions,
            deep_analysis_running_count=deep.get("RUNNING", 0),
            deep_analysis_completed_count=deep_completed,
            deep_analysis_pending_count=deep.get("PENDING", 0),
            hypothesis_count=registered_hypotheses,
            finding_count=finding_count,
            resume_action=(
                "CHECK_USAGE_TELEMETRY"
                if status == "PAUSED"
                and error_code
                in {
                    "LLM_TOKEN_USAGE_UNAVAILABLE",
                    "LLM_COST_USAGE_UNAVAILABLE",
                }
                else "INCREASE_BUDGET_AND_RESUME"
                if status == "PAUSED"
                else None
            ),
            denominator_change_reason=(
                "NEW_HYPOTHESIS_REGISTERED" if registered_hypotheses > 1 else None
            ),
        )

    @staticmethod
    def _status(
        checkpoints: tuple[StageCheckpoint, ...],
        terminal_hypotheses: int,
        hypothesis_count: int,
        *,
        static_disposition: Literal["FULL", "PARTIAL"] = "FULL",
        candidate_pipeline_version: int = 0,
        candidate_counts: Mapping[str, int] | None = None,
        candidate_deep_counts: Mapping[str, int] | None = None,
        candidate_terminal_valid: bool = False,
        candidate_terminal_status: Literal["COMPLETE", "PARTIAL"] | None = None,
    ) -> tuple[
        Literal["RUNNING", "PAUSED", "BLOCKED", "FAILED", "COMPLETE", "PARTIAL"],
        StageCheckpoint,
    ]:
        current = max(checkpoints, key=lambda item: item.updated_at)
        if candidate_pipeline_version >= 1:
            running = [
                item for item in checkpoints if item.status is StageStatus.RUNNING
            ]
            if running:
                return "RUNNING", max(running, key=lambda item: item.updated_at)
            failed = [
                item
                for item in checkpoints
                if item.status is StageStatus.FAILED
                and item.error_code not in _BUDGET_CODES
            ]
            if failed:
                return "FAILED", _visible_child_error(
                    failed, max(failed, key=lambda item: item.updated_at)
                )
            blocked = [
                item
                for item in checkpoints
                if item.status is StageStatus.BLOCKED
                and item.error_code not in _BUDGET_CODES
            ]
            if blocked:
                return "BLOCKED", _visible_child_error(
                    blocked, max(blocked, key=lambda item: item.updated_at)
                )
            if (candidate_counts or {}).get("ERROR", 0) or (
                candidate_deep_counts or {}
            ).get("ERROR", 0):
                return "BLOCKED", current
            paused = [
                item
                for item in checkpoints
                if item.status in {StageStatus.BLOCKED, StageStatus.FAILED}
                and item.error_code in _BUDGET_CODES
            ]
            if paused:
                return "PAUSED", max(paused, key=lambda item: item.updated_at)
        # An active stage is the current analysis, even when an earlier
        # hypothesis has already stopped. Once idle, failed outranks blocked.
        for status in (StageStatus.RUNNING, StageStatus.FAILED, StageStatus.BLOCKED):
            matches = [item for item in checkpoints if item.status is status]
            if matches:
                if status is StageStatus.BLOCKED:
                    operational = [
                        item for item in matches if item.error_code not in _BUDGET_CODES
                    ]
                    if (
                        operational
                        or (candidate_counts or {}).get("ERROR", 0)
                        or (candidate_deep_counts or {}).get("ERROR", 0)
                    ):
                        return "BLOCKED", max(
                            operational or matches, key=lambda item: item.updated_at
                        )
                    return "PAUSED", max(matches, key=lambda item: item.updated_at)
                if status is StageStatus.FAILED:
                    return "FAILED", max(matches, key=lambda item: item.updated_at)
                return "RUNNING", max(matches, key=lambda item: item.updated_at)
        if candidate_pipeline_version >= 1:
            if candidate_counts is None:
                return "RUNNING", current
            deep = candidate_deep_counts or {}
            if candidate_counts.get("ERROR", 0) or deep.get("ERROR", 0):
                return "BLOCKED", current
            deep_eligible = candidate_counts.get("INCLUDE", 0) + candidate_counts.get(
                "UNDECIDED", 0
            )
            deep_terminal = (
                deep.get("COMPLETE", 0)
                + deep.get("NO_HYPOTHESIS", 0)
                + deep.get("INCONCLUSIVE", 0)
            )
            if (
                candidate_counts.get("PENDING", 0)
                or deep.get("PENDING", 0)
                or deep.get("RUNNING", 0)
                or deep_terminal < deep_eligible
                or terminal_hypotheses != hypothesis_count
                or not candidate_terminal_valid
                or not all(
                    any(
                        item.stage is stage and item.status is StageStatus.SUCCEEDED
                        for item in checkpoints
                    )
                    for stage in _ANALYSIS_STAGES
                )
            ):
                return "RUNNING", current
            return (
                candidate_terminal_status
                if candidate_pipeline_version >= 2 and candidate_terminal_status
                else "PARTIAL"
                if static_disposition == "PARTIAL"
                else "COMPLETE"
            ), current
        if hypothesis_count > 0 and terminal_hypotheses == hypothesis_count:
            return (
                "PARTIAL" if static_disposition == "PARTIAL" else "COMPLETE"
            ), current
        return "RUNNING", current


__all__ = ["ProgressProjector", "verified_surface_coverage_counts"]
