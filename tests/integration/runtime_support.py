"""Literal valid wire inputs for persistent runtime tests."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest, Record
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from sastsimi.storage.repositories import SQLiteRecordStore
from tests.unit.contracts.test_core_models import action, meta, work

NOW = datetime(2026, 9, 7, tzinfo=UTC)


class TestClock:
    __test__ = False
    tick = 0

    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        return self.tick


class TestIds:
    __test__ = False
    index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind("generated-" + str(self.index))


def metadata(kind: str, name: str, *, code: bool = False) -> dict[str, Any]:
    return meta(code, record_id=name, logical_record_id=name, record_type=kind)


def units(**changes: Any) -> dict[str, Any]:
    return (
        dict(
            elapsed_ms=0,
            work_count=0,
            llm_call_count=0,
            retry_count=0,
            cost_minor_units=0,
            currency="USD",
        )
        | changes
    )


class Harness:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "runtime.db")
        upgrade(self.database)
        self.records = SQLiteRecordStore(self.database)
        self.clock = TestClock()
        self.ids = TestIds()

    def publish(self, record: Record) -> dict[str, Any]:
        exact = self.records.stage_record(record)
        with self.database.write() as connection:
            self.records.publish(connection, exact)
        return exact.model_dump(mode="json")

    def execution(self, max_work: int = 2) -> ExecutionBudgetProfile:
        source = ActionRequest.model_validate_json(
            json.dumps(action(meta=metadata("action_request", "approval")))
        )
        approval = self.publish(source)
        return ExecutionBudgetProfile.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("execution_budget_profile", "execution"),
                    profile_key="approved",
                    purpose="PRODUCTION",
                    max_analysis_elapsed_ms=1000,
                    max_total_cost_minor_units=100,
                    currency="USD",
                    pricing_revision_ref=approval,
                    max_total_work=max_work,
                    max_total_llm_calls=2,
                    max_total_retries=2,
                    max_parallel_work=1,
                    approval_ref=approval,
                    approved_by="R8",
                    approved_at="2026-09-07T00:00:00Z",
                    status="ACTIVE",
                )
            )
        )

    def reservation(
        self, scope: dict[str, Any], name: str = "reserve", **requested: Any
    ) -> BudgetReservationRequest:
        candidate = WorkExecutionState.model_validate_json(
            json.dumps(
                work(
                    meta=metadata("work_execution_state", name + "-work"),
                    work_id=name + "-work",
                    dedupe_key=("b" if name == "reserve" else "c") * 64,
                )
            )
        )
        work_ref = self.records.stage_record(candidate).model_dump(mode="json")
        request = ActionRequest.model_validate_json(
            json.dumps(
                action(
                    meta=metadata("action_request", name + "-action"),
                    action_id=name + "-action",
                )
            )
        )
        action_ref = self.publish(request)
        return BudgetReservationRequest(
            BudgetReservation.model_validate_json(
                json.dumps(
                    dict(
                        meta=metadata("budget_reservation", name),
                        reservation_id=name,
                        budget_binding_ref=scope,
                        action_ref=action_ref,
                        work_ref=work_ref,
                        requested_units=units(**requested),
                        status="RESERVED",
                        ledger_entry_ref=None,
                        reserved_at="2026-09-07T00:00:00Z",
                        finalized_at=None,
                    )
                )
            )
        )

    def binding(
        self, execution_ref: dict[str, Any]
    ) -> tuple[BudgetProfileBinding, dict[str, Any]]:
        workspace = CodeWorkspace.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("code_workspace", "workspace"),
                    workspace_id="w1",
                    analysis_id="a1",
                    repository_url="https://example.invalid/fixture",
                    commit_id="c1",
                    status="READY",
                )
            )
        )
        workspace_ref = self.publish(workspace)
        work_profile = WorkBudgetProfile.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("work_budget_profile", "limits", code=True),
                    profile_key="limits",
                    purpose="PRODUCTION",
                    limits=[
                        dict(
                            limit_key="static",
                            work_type="STATIC_TOOL",
                            operation_kind="STATIC_TOOL",
                            agent_role="STATIC_ANALYSIS",
                            timeout_ms=1000,
                            max_attempts=2,
                            max_calls_per_work=2,
                            max_items_per_work=10,
                        )
                    ],
                    unlisted_operation="DENY",
                    status="ACTIVE",
                )
            )
        )
        verification = VerificationBudgetProfile.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata(
                        "verification_budget_profile", "verification-budget", code=True
                    ),
                    profile_key="verification",
                    max_verification_elapsed_ms=1000,
                    max_work_per_verification=5,
                    max_llm_calls_per_verification=5,
                    max_retries_per_work=1,
                    max_parallel_evidence_calls=2,
                    status="ACTIVE",
                )
            )
        )
        dynamic = DynamicReproductionLifecycleProfile.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata(
                        "dynamic_reproduction_lifecycle_profile",
                        "dynamic-budget",
                        code=True,
                    ),
                    profile_key="dynamic",
                    preflight_budget_ref=self.publish(work_profile),
                    preflight_budget_source="WORK_REMAINING_TIME",
                    max_new_attempts=2,
                    status="ACTIVE",
                    created_at="2026-09-07T00:00:00Z",
                )
            )
        )
        binding = BudgetProfileBinding.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("budget_profile_binding", "binding", code=True),
                    binding_key="binding",
                    purpose="PRODUCTION",
                    execution_budget_profile_ref=execution_ref,
                    work_budget_profile_ref=self.publish(work_profile),
                    verification_budget_profile_ref=self.publish(verification),
                    dynamic_lifecycle_profile_ref=self.publish(dynamic),
                    approval_ref=execution_ref,
                    approved_by="R8",
                    approved_at="2026-09-07T00:00:00Z",
                    status="ACTIVE",
                )
            )
        )
        return binding, workspace_ref
