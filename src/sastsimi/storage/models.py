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
