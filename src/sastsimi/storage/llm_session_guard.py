"""Resolve resumable LLM sessions from durable, attempt-owned provenance."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    Decision,
    UseStatus,
)
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus

from . import models
from .codec import decode
from .repositories import SQLiteRecordStore


class LLMParentSessionGuard:
    """Allow continuation only from a successful invocation in this work attempt."""

    def __init__(self, records: SQLiteRecordStore) -> None:
        self._records = records

    def require_compatible_parent(
        self, request: LLMInvocationRequest, work: WorkExecutionState
    ) -> None:
        parent_session_ref = request.parent_session_ref
        if parent_session_ref is None:
            raise ValueError("LLM_PARENT_SESSION_NOT_COMPATIBLE")
        if (
            work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or request.meta.attempt_id != work.active_attempt_id
        ):
            raise ValueError("LLM_PARENT_SESSION_NOT_COMPATIBLE")

        with self._records.database.engine.connect() as connection:
            logs = tuple(
                item
                for item in self._published(connection, LLMInvocationLog.KIND)
                if isinstance(item, LLMInvocationLog)
                and item.session_ref == parent_session_ref
            )
            results = tuple(
                item
                for item in self._published(connection, LLMInvocationResult.KIND)
                if isinstance(item, LLMInvocationResult)
                and item.session_ref == parent_session_ref
            )
            for log in logs:
                result = next(
                    (
                        item
                        for item in results
                        if item.llm_call_id == log.llm_call_id
                        and self._same_scope(item, request)
                    ),
                    None,
                )
                if result is None or not self._compatible_invocation(
                    log, result, request
                ):
                    continue
                try:
                    decision = self._records.resolve(
                        connection, log.action_decision_ref
                    )
                    if not isinstance(decision, ActionDecision):
                        continue
                    action = self._records.resolve(connection, decision.action_ref)
                    if not isinstance(action, ActionRequest) or action.work_ref is None:
                        continue
                    parent_work = self._records.resolve(connection, action.work_ref)
                except (LookupError, ValueError):
                    continue
                if (
                    decision.decision == Decision.ALLOW
                    and decision.use_status == UseStatus.USED
                    and isinstance(parent_work, WorkExecutionState)
                    and parent_work.work_id == work.work_id
                    and parent_work.active_attempt_id == work.active_attempt_id
                    and all(
                        getattr(parent_work.meta, field, None)
                        == getattr(request.meta, field)
                        for field in (
                            "analysis_id",
                            "workspace_id",
                            "commit_id",
                            "hypothesis_id",
                        )
                    )
                ):
                    return
        raise ValueError("LLM_PARENT_SESSION_NOT_COMPATIBLE")

    def _published(self, connection: Connection, kind: str) -> tuple[object, ...]:
        rows = connection.execute(
            select(models.records.c.kind, models.records.c.payload)
            .join(models.record_revisions)
            .where(models.records.c.kind == kind)
        ).mappings()
        return tuple(decode(row["kind"], row["payload"]) for row in rows)

    @staticmethod
    def _same_scope(value: object, request: LLMInvocationRequest) -> bool:
        meta = getattr(value, "meta", None)
        return meta is not None and all(
            getattr(meta, field, None) == getattr(request.meta, field)
            for field in (
                "analysis_id",
                "workspace_id",
                "commit_id",
                "hypothesis_id",
                "attempt_id",
            )
        )

    def _compatible_invocation(
        self,
        log: LLMInvocationLog,
        result: LLMInvocationResult,
        request: LLMInvocationRequest,
    ) -> bool:
        return (
            log.status == result.status == "SUCCEEDED"
            and log.session_ref == result.session_ref == request.parent_session_ref
            and log.llm_call_id == result.llm_call_id
            and log.agent_role == request.agent_role
            and log.task_kind == request.task_kind
            and log.purpose == result.purpose == request.purpose
            and log.provider_profile_ref == request.provider_profile_ref
            and log.model == result.model == request.model
            and log.prompt_registry_entry_ref == request.prompt_registry_entry_ref
            and log.prompt_template_ref == request.prompt_template_ref
            and log.prompt_template_version == request.prompt_template_version
            and self._same_scope(log, request)
            and self._same_scope(result, request)
        )


__all__ = ["LLMParentSessionGuard"]
