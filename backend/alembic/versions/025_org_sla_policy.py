"""Add SLA policy to organizations and finding activity tracking.

Revision ID: 025
Revises: 024
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "025"
down_revision = "024"


def upgrade():
    # Add SLA policy to organizations (days per severity level)
    op.add_column("organizations", sa.Column("sla_policy", JSONB, nullable=True, server_default='{"critical": 1, "high": 3, "medium": 7, "low": 30, "info": 90}'))

    # Add activity log to findings (more comprehensive than recheck_history)
    op.add_column("findings", sa.Column("activity_log", JSONB, nullable=True, server_default='[]'))

    # Add SLA-related computed helper fields
    op.add_column("findings", sa.Column("sla_breached", sa.Boolean(), nullable=True, server_default="false"))


def downgrade():
    op.drop_column("findings", "sla_breached")
    op.drop_column("findings", "activity_log")
    op.drop_column("organizations", "sla_policy")
