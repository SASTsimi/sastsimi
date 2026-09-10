"""Bind trusted output closures to the exact issued action and decision."""

import sqlalchemy as sa
from alembic import op

revision = "0003_runtime_guards"
down_revision = "0002_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "action_output_closures",
        sa.Column(
            "action_id",
            sa.Text(),
            sa.ForeignKey("action_requests.action_id"),
            primary_key=True,
        ),
        sa.Column("decision_ref", sa.Text(), nullable=False),
        sa.Column("output_refs", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("action_output_closures")
