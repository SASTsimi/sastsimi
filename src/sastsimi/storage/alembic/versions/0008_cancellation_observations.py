"""Persist append-only exact cancellation observations.

Revision ID: 0008_cancellation_observations
Revises: 0007_prompt_analysis_scope
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_cancellation_observations"
down_revision = "0007_prompt_analysis_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cancellation_observations",
        sa.Column("observation_key", sa.Text(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Text(),
            sa.ForeignKey("analysis_runs.analysis_id"),
            nullable=False,
        ),
        sa.Column("work_id", sa.Text(), nullable=False),
        sa.Column("attempt_id", sa.Text(), nullable=False),
        sa.Column("action_ref", sa.Text(), nullable=False),
        sa.Column("issued_decision_ref", sa.Text(), nullable=False),
        sa.Column("decision_ref", sa.Text(), nullable=False),
        sa.Column("target_kind", sa.Text(), nullable=False),
        sa.Column("resource_kind", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("resource_ref", sa.Text()),
        sa.Column("resource_tag", sa.Text()),
        sa.Column("labels", sa.Text(), nullable=False),
        sa.Column("lookup_by_name", sa.Integer(), nullable=False),
        sa.Column("preservation_reason", sa.Text()),
        sa.Column("inventory_fingerprint", sa.Text(), nullable=False),
        sa.Column("resource_ordinal", sa.Integer(), nullable=False),
        sa.Column("resource_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text()),
        sa.Column("observed_at", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("cancellation_observations")
