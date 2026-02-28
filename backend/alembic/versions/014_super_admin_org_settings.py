"""Add super_admin role support and org_settings for per-org JIRA/LLM

Revision ID: 014
Revises: 013
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # org_settings: per-organization JIRA, LLM, etc.
    op.create_table(
        "org_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_org_settings_org_key", "org_settings", ["organization_id", "key"], unique=True)

    # role: allow super_admin (existing: admin, lead, tester, viewer)
    # No schema change needed - role is varchar(20), 'super_admin' fits


def downgrade() -> None:
    op.drop_table("org_settings")
