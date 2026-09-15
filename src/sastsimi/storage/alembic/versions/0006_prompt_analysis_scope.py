"""Scope active prompt selections to one analysis checkout.

Revision ID: 0007_prompt_analysis_scope
Revises: 0006_run_control
"""

import json

import sqlalchemy as sa
from alembic import op

revision = "0007_prompt_analysis_scope"
down_revision = "0006_run_control"
branch_labels = None
depends_on = None


def _scoped_table(name: str) -> sa.Table:
    return op.create_table(
        name,
        sa.Column("analysis_id", sa.Text(), primary_key=True),
        sa.Column("workspace_id", sa.Text(), primary_key=True),
        sa.Column("commit_id", sa.Text(), primary_key=True),
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
        sa.UniqueConstraint("logical_record_id"),
    )


def upgrade() -> None:
    connection = op.get_bind()
    old = sa.table(
        "prompt_active_entries",
        sa.column("agent_role"),
        sa.column("task_kind"),
        sa.column("purpose"),
        sa.column("logical_record_id"),
        sa.column("record_id"),
        sa.column("state_version"),
    )
    records = sa.table(
        "records",
        sa.column("record_id"),
        sa.column("payload"),
    )
    replacement = _scoped_table("prompt_active_entries_scoped")
    rows = connection.execute(
        sa.select(old, records.c.payload).select_from(
            old.join(records, old.c.record_id == records.c.record_id)
        )
    ).mappings()
    for row in rows:
        payload = json.loads(row["payload"])
        metadata = payload.get("meta", {})
        scope = tuple(
            metadata.get(name) for name in ("analysis_id", "workspace_id", "commit_id")
        )
        if any(not isinstance(value, str) or not value for value in scope):
            raise ValueError("PROMPT_ACTIVE_SCOPE_MISSING")
        connection.execute(
            replacement.insert().values(
                analysis_id=scope[0],
                workspace_id=scope[1],
                commit_id=scope[2],
                agent_role=row["agent_role"],
                task_kind=row["task_kind"],
                purpose=row["purpose"],
                logical_record_id=row["logical_record_id"],
                record_id=row["record_id"],
                state_version=row["state_version"],
            )
        )
    op.drop_table("prompt_active_entries")
    op.rename_table("prompt_active_entries_scoped", "prompt_active_entries")


def downgrade() -> None:
    connection = op.get_bind()
    scoped = sa.table(
        "prompt_active_entries",
        sa.column("agent_role"),
        sa.column("task_kind"),
        sa.column("purpose"),
        sa.column("logical_record_id"),
        sa.column("record_id"),
        sa.column("state_version"),
    )
    old = op.create_table(
        "prompt_active_entries_global",
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
        sa.UniqueConstraint("logical_record_id"),
    )
    rows = connection.execute(sa.select(scoped)).mappings()
    for row in rows:
        connection.execute(
            old.insert().values(
                agent_role=row["agent_role"],
                task_kind=row["task_kind"],
                purpose=row["purpose"],
                logical_record_id=row["logical_record_id"],
                record_id=row["record_id"],
                state_version=row["state_version"],
            )
        )
    op.drop_table("prompt_active_entries")
    op.rename_table("prompt_active_entries_global", "prompt_active_entries")
