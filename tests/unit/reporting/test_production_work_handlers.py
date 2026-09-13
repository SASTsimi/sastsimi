from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.work import SubjectType, WorkType
from sastsimi.reporting.finding_normalization import FindingNormalizationService
from sastsimi.reporting.work_handlers import (
    FindingNormalizeHandler,
    ReporterDraftWorkflow,
    ReporterInputResolver,
    ReporterWorkHandler,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.unit.orchestration.test_production_llm_work_handlers import _context, _ref


class _Publisher:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def complete(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((*args, kwargs))
        return SimpleNamespace(output_refs=(_ref("committed", "terminal"),))


@pytest.mark.asyncio
async def test_finding_handler_terminally_commits_instead_of_only_staging() -> None:
    verification = _ref("verification_result", "verification")
    cwe = _ref("cwe_label", "cwe")
    technical = _ref("technical_evidence_review", "technical")
    scope = _ref("rule_scope_impact_review", "scope")
    context = _context(
        WorkType.FINDING_NORMALIZE,
        (verification, cwe, technical, scope),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=_ref("work_execution_state", "rule-scope-work"),
    )
    finding = object()
    service = SimpleNamespace(assemble=lambda **_kwargs: finding)
    publisher = _Publisher()
    handler = FindingNormalizeHandler(
        service=cast(FindingNormalizationService, service),
        records=SimpleNamespace(),
        publisher=cast(WorkflowRunner, publisher),
        identity_ref=_ref("role_identity", "verification-identity"),
    )

    result = await handler.execute(context)

    assert result.output_refs[0].data_kind == "committed"
    assert len(publisher.calls) == 1
    assert publisher.calls[0][2] == "VERIFICATION"
    assert publisher.calls[0][3] == (finding,)


@pytest.mark.asyncio
async def test_reporter_handler_fails_closed_without_terminal_publisher() -> None:
    context = _context(WorkType.REPORT_DRAFT, ())
    workflow = SimpleNamespace()

    async def _draft(**_kwargs: Any) -> Any:
        return SimpleNamespace(
            draft=object(),
            draft_ref=_ref("report_draft", "draft"),
            save_input_refs=(),
        )

    workflow.create_draft = _draft
    handler = ReporterWorkHandler(
        workflow=cast(ReporterDraftWorkflow, workflow),
        resolve_inputs=cast(
            ReporterInputResolver, lambda _context: (object(), object())
        ),
    )

    with pytest.raises(ValueError, match="REPORT_DRAFT_PUBLISHER_REQUIRED"):
        await handler.execute(context)
