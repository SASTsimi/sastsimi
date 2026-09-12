"""Persist exact Chaining pools and globally unique match identities.

Revision ID: 0005_chaining_matches
Revises: 0004_prompt_runtime
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_chaining_matches"
down_revision = "0004_prompt_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chaining_cohorts",
        sa.Column("cohort_id", sa.Text(), primary_key=True),
        sa.Column("source_update_ref", sa.Text(), nullable=False, unique=True),
        sa.Column("analysis_id", sa.Text(), nullable=False),
        sa.Column("workspace_id", sa.Text(), nullable=False),
        sa.Column("commit_id", sa.Text(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
    )
    op.create_table(
        "chaining_work_pools",
        sa.Column(
            "work_id",
            sa.Text(),
            sa.ForeignKey("work_states.work_id"),
            primary_key=True,
        ),
        sa.Column(
            "cohort_id",
            sa.Text(),
            sa.ForeignKey("chaining_cohorts.cohort_id"),
            nullable=False,
        ),
        sa.Column("member_order", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Text(), nullable=False),
        sa.Column("workspace_id", sa.Text(), nullable=False),
        sa.Column("commit_id", sa.Text(), nullable=False),
        sa.Column("trigger_work_ref", sa.Text(), nullable=False, unique=True),
        sa.Column("trigger_primitive_ref", sa.Text(), nullable=False),
        sa.Column("index_refs", sa.Text(), nullable=False),
        sa.Column("considered_primitive_refs", sa.Text(), nullable=False),
        sa.Column("pool_hash", sa.Text(), nullable=False),
        sa.UniqueConstraint("cohort_id", "member_order"),
        sa.UniqueConstraint("analysis_id", "trigger_primitive_ref"),
    )
    op.create_table(
        "chaining_match_reservations",
        sa.Column("analysis_id", sa.Text(), primary_key=True),
        sa.Column("primitive_match_id", sa.Text(), primary_key=True),
        sa.Column("upstream_result_ref", sa.Text(), nullable=False),
        sa.Column("downstream_input_ref", sa.Text(), nullable=False),
        sa.Column("matched_input_id", sa.Text(), nullable=False),
        sa.Column("source_result_ref", sa.Text(), nullable=False),
        sa.UniqueConstraint(
            "analysis_id",
            "upstream_result_ref",
            "downstream_input_ref",
            "matched_input_id",
            name="uq_chaining_directional_triple",
        ),
    )


def downgrade() -> None:
    op.drop_table("chaining_match_reservations")
    op.drop_table("chaining_work_pools")
    op.drop_table("chaining_cohorts")
