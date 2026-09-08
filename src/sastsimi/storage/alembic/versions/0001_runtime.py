"""Initial local runtime foundation.

Revision ID: 0001_runtime
Revises: None
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_runtime"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_runs",
        sa.Column("analysis_id", sa.Text, primary_key=True),
        sa.Column("payload", sa.Text, nullable=False),
    )
    op.create_table(
        "records",
        sa.Column("record_id", sa.Text, primary_key=True),
        sa.Column("logical_record_id", sa.Text, nullable=False),
        sa.Column("revision_number", sa.Integer, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("ref", sa.Text, nullable=False),
    )
    op.create_table(
        "record_revisions",
        sa.Column(
            "record_id", sa.Text, sa.ForeignKey("records.record_id"), primary_key=True
        ),
        sa.Column("logical_record_id", sa.Text, nullable=False),
        sa.Column("revision_number", sa.Integer, nullable=False),
        sa.UniqueConstraint("logical_record_id", "revision_number"),
    )
    op.create_table(
        "current_records",
        sa.Column("logical_record_id", sa.Text, primary_key=True),
        sa.Column(
            "record_id",
            sa.Text,
            sa.ForeignKey("record_revisions.record_id"),
            nullable=False,
        ),
        sa.Column("state_version", sa.Integer, nullable=False),
    )

    op.create_table(
        "budget_profiles",
        sa.Column("analysis_id", sa.Text, primary_key=True),
        sa.Column("kind", sa.Text, primary_key=True),
        sa.Column("ref", sa.Text, nullable=False),
    )
    op.create_table(
        "budget_reservations",
        sa.Column("reservation_id", sa.Text, primary_key=True),
        sa.Column("analysis_id", sa.Text, nullable=False),
        sa.Column("action_id", sa.Text, nullable=False, unique=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("initial_ref", sa.Text, nullable=False),
        sa.Column("claimed", sa.Integer, nullable=False),
    )
    op.create_table(
        "budget_ledger_entries",
        sa.Column("ledger_entry_id", sa.Text, primary_key=True),
        sa.Column(
            "reservation_id",
            sa.Text,
            sa.ForeignKey("budget_reservations.reservation_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("analysis_id", sa.Text, nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.UniqueConstraint("analysis_id", "sequence"),
    )

    op.create_table(
        "work_states",
        sa.Column("work_id", sa.Text, primary_key=True),
        sa.Column("analysis_id", sa.Text, nullable=False),
        sa.Column("registration_key", sa.Text, nullable=False, unique=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("state_version", sa.Integer, nullable=False),
        sa.Column("active_attempt_id", sa.Text),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("worker_id", sa.Text),
        sa.Column("lease_expires_at", sa.Text),
    )
    op.create_table(
        "work_attempts",
        sa.Column("attempt_id", sa.Text, primary_key=True),
        sa.Column(
            "work_id", sa.Text, sa.ForeignKey("work_states.work_id"), nullable=False
        ),
        sa.Column("attempt_number", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.UniqueConstraint("work_id", "attempt_number"),
    )
    op.create_index(
        "one_active_attempt",
        "work_attempts",
        ["work_id"],
        unique=True,
        sqlite_where=sa.text("status = 'RUNNING'"),
    )
    op.create_table(
        "action_decisions",
        sa.Column("decision_id", sa.Text, primary_key=True),
        sa.Column("action_id", sa.Text, nullable=False, unique=True),
        sa.Column("payload", sa.Text, nullable=False),
    )

    op.create_table(
        "transition_commits",
        sa.Column("transition_commit_id", sa.Text, primary_key=True),
        sa.Column(
            "work_id", sa.Text, sa.ForeignKey("work_states.work_id"), nullable=False
        ),
        sa.Column("expected_state_version", sa.Integer, nullable=False),
        sa.Column("candidate_binding", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("request", sa.Text, nullable=False),
        sa.UniqueConstraint("work_id", "expected_state_version", "candidate_binding"),
    )
    op.create_table(
        "artifacts",
        sa.Column("content_hash", sa.Text, primary_key=True),
        sa.Column("path", sa.Text, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("artifacts")
    op.drop_table("transition_commits")
    op.drop_table("action_decisions")
    op.drop_table("work_attempts")
    op.drop_table("work_states")
    op.drop_table("budget_ledger_entries")
    op.drop_table("budget_reservations")
    op.drop_table("budget_profiles")
    op.drop_table("current_records")
    op.drop_table("record_revisions")
    op.drop_table("records")
    op.drop_table("analysis_runs")
