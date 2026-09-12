"""Initial proposal registration is a derived non-LLM terminal-commit projection."""

from sqlalchemy import Connection, select

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    ProposalProcessState,
    VulnerabilityHypothesis,
    validate_hypothesis_registration,
    validate_proposal_facts,
)
from sastsimi.contracts.ids import HypothesisId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import FindingIndexState
from sastsimi.contracts.static import (
    CodeWorkspace,
    RuleExecutionRecord,
    StaticFactBundle,
    validate_static_current,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkType,
)
from sastsimi.ports.dto import Record

from . import models
from .codec import REF_ADAPTER, reference
from .committed_outputs import require_committed
from .records import fresh_meta
from .run_states import get_run
from .stage_policy import current
from .work_service import WorkService


def hypothesis_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    *,
    publish: bool,
) -> tuple[Record, ...]:
    proposals = [record for record in outputs if isinstance(record, HypothesisProposal)]
    if not proposals or work.work_type != "HYPOTHESIS_PROPOSAL":
        return ()
    if len(proposals) != len(outputs):
        raise ValueError("HYPOTHESIS_PROPOSAL_BATCH_KIND_MISMATCH")
    if (
        len({proposal.proposal_id for proposal in proposals}) != len(proposals)
        or len(
            {
                question.question_id
                for proposal in proposals
                for question in proposal.falsification_questions
            }
        )
        != sum(len(proposal.falsification_questions) for proposal in proposals)
        or len(
            {
                check.validation_id
                for proposal in proposals
                for check in proposal.validation_checks
            }
        )
        != sum(len(proposal.validation_checks) for proposal in proposals)
    ):
        raise ValueError("HYPOTHESIS_PROPOSAL_BATCH_ID_CONFLICT")
    if len(proposals) > 1:
        projected: list[Record] = []
        for proposal in proposals:
            projected.extend(
                hypothesis_projection(
                    works,
                    connection,
                    work,
                    (proposal,),
                    publish=publish,
                )
            )
        return tuple(projected)
    proposal = proposals[0]
    records = works.records
    if proposal.origin == "INITIAL":
        refs = [ref for ref in work.input_refs if ref.data_kind == "static_fact_bundle"]
        if len(refs) != 1:
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        bundle_ref = refs[0]
        if not isinstance(bundle_ref, StoredDataRef):
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        current(records, connection, bundle_ref)
        bundle = records.resolve(connection, bundle_ref)
        if not isinstance(bundle, StaticFactBundle):
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        commits = [
            commit
            for payload in connection.execute(
                select(models.transition_commits.c.payload).where(
                    models.transition_commits.c.state == "COMMITTED",
                )
            ).scalars()
            if bundle_ref
            in (commit := TransitionCommit.model_validate_json(payload)).output_refs
        ]
        if len(commits) != 1:
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        commit = commits[0]
        normalized = works.get(str(commit.work_id), connection)
        attempt_payload = connection.execute(
            select(models.work_attempts.c.payload).where(
                models.work_attempts.c.attempt_id == str(commit.attempt_id),
            )
        ).scalar_one()
        attempt = WorkAttempt.model_validate_json(attempt_payload)
        run = get_run(connection, str(work.meta.analysis_id))
        if run.workspace_ref is None:
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        workspace = records.resolve(connection, run.workspace_ref)
        if not isinstance(workspace, CodeWorkspace):
            raise ValueError("PROPOSAL_STATIC_CLOSURE_REQUIRED")
        rules = tuple(
            records.resolve(connection, item.rule_execution_ref)
            for item in bundle.tool_runs
            if item.rule_execution_ref is not None
        )
        if any(not isinstance(item, RuleExecutionRecord) for item in rules):
            raise ValueError("RULE_EXECUTION_REQUIRED")
        typed_rules = tuple(
            item for item in rules if isinstance(item, RuleExecutionRecord)
        )
        analysis_configs = {item.analysis_config_ref for item in typed_rules}
        if len(analysis_configs) > 1:
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        catalogs = {
            item.rule_catalog_ref: tuple(rule.rule_id for rule in item.rules)
            for item in typed_rules
        }
        validate_static_current(
            bundle,
            bundle_ref,
            workspace,
            normalized,
            commit,
            typed_rules,
            attempt=attempt,
            rule_catalogs=catalogs,
            analysis_config_ref=next(iter(analysis_configs), None),
        )
        validate_proposal_facts(proposal, bundle, bundle_ref)
    else:
        source_kind = (
            "verification_result"
            if proposal.origin == "VERIFICATION"
            else "chaining_result"
        )
        refs = [ref for ref in work.input_refs if ref.data_kind == source_kind]
        if len(refs) != 1 or len(work.input_refs) != 1:
            raise ValueError("PROPOSAL_SOURCE_CLOSURE_REQUIRED")
        source_ref = refs[0]
        current(records, connection, source_ref)
        source = records.resolve(connection, source_ref)
        if proposal.origin == "VERIFICATION" and isinstance(source, VerificationResult):
            require_committed(records, connection, source, WorkType.VERIFICATION)
            children = source.material_child_proposals
            if proposal.parent_hypothesis_ids != (source.meta.hypothesis_id,):
                raise ValueError("PROPOSAL_PARENT_MISMATCH")
        elif proposal.origin == "CHAINING" and isinstance(source, ChainingResult):
            require_committed(records, connection, source, WorkType.CHAINING)
            children = source.chained_hypothesis_proposals
        else:
            raise ValueError("PROPOSAL_SOURCE_CLOSURE_REQUIRED")
        proposal_content = proposal.model_dump(exclude={"meta"})
        if (
            sum(
                item.model_dump(exclude={"meta"}) == proposal_content
                for item in children
            )
            != 1
        ):
            raise ValueError("PROPOSAL_SOURCE_CLOSURE_REQUIRED")
    for wire in connection.execute(
        select(models.records.c.ref)
        .join(
            models.current_records,
            models.current_records.c.record_id == models.records.c.record_id,
        )
        .where(models.records.c.kind == "vulnerability_hypothesis")
    ).scalars():
        prior = records.resolve(connection, REF_ADAPTER.validate_json(wire))
        if isinstance(
            prior, VulnerabilityHypothesis
        ) and prior.proposal_ref == reference(proposal):
            raise ValueError("PROPOSAL_ALREADY_REGISTERED")
    if not publish:
        return ()
    hypothesis_id = works.ids.new(HypothesisId)
    meta = fresh_meta(
        proposal.meta,
        "vulnerability_hypothesis",
        works.clock,
        works.ids,
        hypothesis_id=hypothesis_id,
        attempt_id=None,
    )
    copied = {
        name: getattr(proposal, name)
        for name in (
            "statement",
            "origin",
            "target_entities",
            "target_locations",
            "suspected_path",
            "falsification_questions",
            "validation_checks",
            "parent_hypothesis_ids",
            "source_primitive_match_id",
        )
    }
    hypothesis = VulnerabilityHypothesis.model_validate_json(
        canonical_bytes(
            copied
            | dict(
                meta=meta,
                proposal_ref=reference(proposal),
            )
        )
    )
    validate_hypothesis_registration(hypothesis, proposal)
    process = HypothesisProcessState.model_validate_json(
        canonical_bytes(
            dict(
                meta=fresh_meta(
                    meta, "hypothesis_process_state", works.clock, works.ids
                ),
                proposal_ref=reference(proposal),
                status="REGISTERED",
                verification_assignment_ref=None,
                verification_generation=0,
                verification_work_ref=None,
                verification_result_ref=None,
                started_at=works.clock.now(),
                finished_at=None,
                elapsed_ms=0,
            )
        )
    )
    index = FindingIndexState.model_validate_json(
        canonical_bytes(
            dict(
                meta=fresh_meta(meta, "finding_index_state", works.clock, works.ids),
                state_version=1,
                status="EMPTY",
                finding_ref=None,
                stale_finding_ref=None,
                normalization_work_ref=None,
                last_transition_commit_ref=None,
                invalidated_by_refs=(),
            )
        )
    )
    proposal_state = ProposalProcessState.model_validate_json(
        canonical_bytes(
            dict(
                meta=fresh_meta(
                    proposal.meta,
                    "proposal_process_state",
                    works.clock,
                    works.ids,
                    hypothesis_id=None,
                    attempt_id=None,
                ),
                proposal_ref=reference(proposal),
                status="SCHEMA_VALID",
                duplicate_review_ref=None,
                duplicate_of_hypothesis_ref=None,
                registration_reason="NO_CANDIDATES",
                started_at=proposal.meta.created_at,
                finished_at=works.clock.now(),
                elapsed_ms=0,
            )
        )
    )
    return (proposal_state, hypothesis, process, index)
