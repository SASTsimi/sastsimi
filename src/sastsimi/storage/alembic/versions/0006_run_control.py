"""Add the durable analysis cancellation latch.

Revision ID: 0006_run_control
Revises: 0005_chaining_matches
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_run_control"
down_revision = "0005_chaining_matches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_controls",
        sa.Column(
            "analysis_id",
            sa.Text(),
            sa.ForeignKey("analysis_runs.analysis_id"),
            primary_key=True,
        ),
        sa.Column("cancel_requested_at", sa.Text(), nullable=False),
        sa.Column("cancel_reason", sa.Text(), nullable=False),
        sa.Column("quiescent_at", sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("run_controls")
