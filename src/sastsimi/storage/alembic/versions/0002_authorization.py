"""Persist trusted request and check projections without inferred backfill."""

import sqlalchemy as sa
from alembic import op

revision = "0002_authorization"
down_revision = "0001_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("budget_reservations", sa.Column("item_count", sa.Integer))
    op.create_table(
        "external_dispatches",
        sa.Column("action_id", sa.Text, primary_key=True),
        sa.Column("work_id", sa.Text, nullable=False),
        sa.Column("attempt_id", sa.Text, nullable=False),
        sa.Column("decision_ref", sa.Text, nullable=False),
        sa.Column("reservation_ref", sa.Text, nullable=False),
        sa.Column("prepared_at", sa.Text, nullable=False),
        sa.Column("dispatched_at", sa.Text),
        sa.Column("returned_at", sa.Text),
        sa.Column("provider_request_id", sa.Text),
        sa.Column("idempotency_key", sa.Text),
        sa.Column("reconciled_at", sa.Text),
    )
    op.create_table(
        "action_requests",
        sa.Column("action_id", sa.Text, primary_key=True),
        sa.Column("request_ref", sa.Text, nullable=False),
        sa.Column("decision_ref", sa.Text, nullable=False),
    )
    op.create_table(
        "action_checks",
        sa.Column(
            "action_id",
            sa.Text,
            sa.ForeignKey("action_requests.action_id"),
            primary_key=True,
        ),
        sa.Column("check_type", sa.Text, primary_key=True),
        sa.Column("payload", sa.Text, nullable=False),
    )


def downgrade() -> None:
    op.drop_column("budget_reservations", "item_count")
    op.drop_table("external_dispatches")
    op.drop_table("action_checks")
    op.drop_table("action_requests")
