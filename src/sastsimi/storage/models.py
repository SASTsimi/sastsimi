"""Persistence tables, separate from the immutable Pydantic contracts."""

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()
external_dispatches = Table(
    "external_dispatches",
    metadata,
    Column("action_id", Text, primary_key=True),
    Column("work_id", Text, nullable=False),
    Column("attempt_id", Text, nullable=False),
    Column("decision_ref", Text, nullable=False),
    Column("reservation_ref", Text, nullable=False),
    Column("prepared_at", Text, nullable=False),
    Column("dispatched_at", Text),
    Column("returned_at", Text),
    Column("provider_request_id", Text),
    Column("idempotency_key", Text),
    Column("reconciled_at", Text),
)
analysis_runs = Table(
    "analysis_runs",
    metadata,
    Column("analysis_id", Text, primary_key=True),
    Column("payload", Text, nullable=False),
)
run_controls = Table(
    "run_controls",
    metadata,
    Column(
        "analysis_id",
        Text,
        ForeignKey("analysis_runs.analysis_id"),
        primary_key=True,
    ),
    Column("cancel_requested_at", Text, nullable=False),
    Column("cancel_reason", Text, nullable=False),
    Column("quiescent_at", Text),
)
action_requests = Table(
    "action_requests",
    metadata,
    Column("action_id", Text, primary_key=True),
    Column("request_ref", Text, nullable=False),
    Column("decision_ref", Text, nullable=False),
)
action_checks = Table(
    "action_checks",
    metadata,
    Column(
        "action_id", Text, ForeignKey("action_requests.action_id"), primary_key=True
    ),
    Column("check_type", Text, primary_key=True),
    Column("payload", Text, nullable=False),
)
action_output_closures = Table(
    "action_output_closures",
    metadata,
    Column(
        "action_id", Text, ForeignKey("action_requests.action_id"), primary_key=True
    ),
    Column("decision_ref", Text, nullable=False),
    Column("output_refs", Text, nullable=False),
    Column("content_hash", Text, nullable=False),
)
records = Table(
    "records",
    metadata,
    Column("record_id", Text, primary_key=True),
    Column("logical_record_id", Text, nullable=False),
    Column("revision_number", Integer, nullable=False),
    Column("kind", Text, nullable=False),
    Column("content_hash", Text, nullable=False),
    Column("payload", Text, nullable=False),
    Column("ref", Text, nullable=False),
)
record_revisions = Table(
    "record_revisions",
    metadata,
    Column("record_id", Text, ForeignKey("records.record_id"), primary_key=True),
    Column("logical_record_id", Text, nullable=False),
    Column("revision_number", Integer, nullable=False),
    UniqueConstraint("logical_record_id", "revision_number"),
)
current_records = Table(
    "current_records",
    metadata,
    Column("logical_record_id", Text, primary_key=True),
    Column("record_id", Text, ForeignKey("record_revisions.record_id"), nullable=False),
    Column("state_version", Integer, nullable=False),
)
prompt_active_entries = Table(
    "prompt_active_entries",
    metadata,
    Column("agent_role", Text, primary_key=True),
    Column("task_kind", Text, primary_key=True),
    Column("purpose", Text, primary_key=True),
    Column("logical_record_id", Text, nullable=False),
    Column("record_id", Text, ForeignKey("record_revisions.record_id"), nullable=False),
    Column("state_version", Integer, nullable=False),
    UniqueConstraint("logical_record_id"),
)
budget_profiles = Table(
    "budget_profiles",
    metadata,
    Column("analysis_id", Text, primary_key=True),
    Column("kind", Text, primary_key=True),
    Column("ref", Text, nullable=False),
)
budget_reservations = Table(
    "budget_reservations",
    metadata,
    Column("reservation_id", Text, primary_key=True),
    Column("analysis_id", Text, nullable=False),
    Column("action_id", Text, nullable=False, unique=True),
    Column("status", Text, nullable=False),
    Column("payload", Text, nullable=False),
    Column("initial_ref", Text, nullable=False),
    Column("claimed", Integer, nullable=False, default=0),
    Column("item_count", Integer),
)
budget_ledger_entries = Table(
    "budget_ledger_entries",
    metadata,
    Column("ledger_entry_id", Text, primary_key=True),
    Column(
        "reservation_id",
        Text,
        ForeignKey("budget_reservations.reservation_id"),
        nullable=False,
        unique=True,
    ),
    Column("analysis_id", Text, nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("payload", Text, nullable=False),
    UniqueConstraint("analysis_id", "sequence"),
)
work_states = Table(
    "work_states",
    metadata,
    Column("work_id", Text, primary_key=True),
    Column("analysis_id", Text, nullable=False),
    Column("registration_key", Text, nullable=False, unique=True),
    Column("status", Text, nullable=False),
    Column("state_version", Integer, nullable=False),
    Column("active_attempt_id", Text),
    Column("payload", Text, nullable=False),
    Column("worker_id", Text),
    Column("lease_expires_at", Text),
)
work_attempts = Table(
    "work_attempts",
    metadata,
    Column("attempt_id", Text, primary_key=True),
    Column("work_id", Text, ForeignKey("work_states.work_id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("status", Text, nullable=False),
    Column("payload", Text, nullable=False),
    UniqueConstraint("work_id", "attempt_number"),
)
action_decisions = Table(
    "action_decisions",
    metadata,
    Column("decision_id", Text, primary_key=True),
    Column("action_id", Text, nullable=False, unique=True),
    Column("payload", Text, nullable=False),
)
transition_commits = Table(
    "transition_commits",
    metadata,
    Column("transition_commit_id", Text, primary_key=True),
    Column("work_id", Text, ForeignKey("work_states.work_id"), nullable=False),
    Column("expected_state_version", Integer, nullable=False),
    Column("candidate_binding", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("payload", Text, nullable=False),
    Column("request", Text, nullable=False),
    UniqueConstraint("work_id", "expected_state_version", "candidate_binding"),
)
artifacts = Table(
    "artifacts",
    metadata,
    Column("content_hash", Text, primary_key=True),
    Column("path", Text, nullable=False),
)

# T13 keeps the exact comparison universe independently of current indexes.
# The pool is written before a sibling cohort is exposed as READY, so pair
# ownership can never depend on worker timing or a later index revision.
chaining_cohorts = Table(
    "chaining_cohorts",
    metadata,
    Column("cohort_id", Text, primary_key=True),
    Column("source_update_ref", Text, nullable=False, unique=True),
    Column("analysis_id", Text, nullable=False),
    Column("workspace_id", Text, nullable=False),
    Column("commit_id", Text, nullable=False),
    Column("member_count", Integer, nullable=False),
    Column("status", Text, nullable=False),
)
chaining_work_pools = Table(
    "chaining_work_pools",
    metadata,
    Column(
        "work_id",
        Text,
        ForeignKey("work_states.work_id"),
        primary_key=True,
    ),
    Column(
        "cohort_id",
        Text,
        ForeignKey("chaining_cohorts.cohort_id"),
        nullable=False,
    ),
    Column("member_order", Integer, nullable=False),
    Column("analysis_id", Text, nullable=False),
    Column("workspace_id", Text, nullable=False),
    Column("commit_id", Text, nullable=False),
    Column("trigger_work_ref", Text, nullable=False, unique=True),
    Column("work_generation", Integer, nullable=False),
    Column("input_hash", Text, nullable=False),
    Column("trigger_primitive_ref", Text, nullable=False),
    Column("index_refs", Text, nullable=False),
    Column("considered_primitive_refs", Text, nullable=False),
    Column("pool_hash", Text, nullable=False),
    UniqueConstraint("cohort_id", "member_order"),
    UniqueConstraint("analysis_id", "trigger_primitive_ref"),
)
chaining_match_reservations = Table(
    "chaining_match_reservations",
    metadata,
    Column("analysis_id", Text, primary_key=True),
    Column("primitive_match_id", Text, primary_key=True),
    Column("upstream_result_ref", Text, nullable=False),
    Column("downstream_input_ref", Text, nullable=False),
    Column("matched_input_id", Text, nullable=False),
    Column("source_result_ref", Text, nullable=False),
    UniqueConstraint(
        "analysis_id",
        "upstream_result_ref",
        "downstream_input_ref",
        "matched_input_id",
        name="uq_chaining_directional_triple",
    ),
)
