"""Atomically select one ACTIVE prompt per role, task and purpose.

Revision ID: 0004_prompt_runtime
Revises: 0003_runtime_guards
"""

import json

import sqlalchemy as sa
from alembic import op

revision = "0004_prompt_runtime"
down_revision = "0003_runtime_guards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = op.create_table(
        "prompt_active_entries",
        sa.Column("agent_role", sa.Text(), primary_key=True),
        sa.Column("task_kind", sa.Text(), primary_key=True),
        sa.Column("purpose", sa.Text(), primary_key=True),
        sa.Column("logical_record_id", sa.Text(), nullable=False),
        sa.Column(
            "record_id",
            sa.Text(),
            sa.ForeignKey("record_revisions.record_id"),
            nullable=False,
        ),
        sa.Column("state_version", sa.Integer(), nullable=False),
    )
    connection = op.get_bind()
    records = sa.table(
        "records",
        sa.column("record_id"),
        sa.column("logical_record_id"),
        sa.column("kind"),
        sa.column("payload"),
    )
    current_records = sa.table(
        "current_records",
        sa.column("logical_record_id"),
        sa.column("record_id"),
    )
    rows = connection.execute(
        sa.select(
            records.c.payload,
            records.c.logical_record_id,
            records.c.record_id,
        )
        .select_from(
            records.join(
                current_records, records.c.record_id == current_records.c.record_id
            )
        )
        .where(records.c.kind == "prompt_registry_entry")
    ).mappings()
    for row in rows:
        payload = json.loads(row["payload"])
        if payload.get("status") != "ACTIVE":
            continue
        connection.execute(
            table.insert().values(
                agent_role=payload["agent_role"],
                task_kind=payload["task_kind"],
                purpose=payload["purpose"],
                logical_record_id=row["logical_record_id"],
                record_id=row["record_id"],
                state_version=1,
            )
        )


def downgrade() -> None:
    op.drop_table("prompt_active_entries")
