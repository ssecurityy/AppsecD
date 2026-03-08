"""SAST policy pr_action: audit vs block for PR reviews.

Revision ID: 033_pr_action
Revises: 032_scan_stats
"""
from alembic import op
import sqlalchemy as sa

revision = "033_pr_action"
down_revision = "032_scan_stats"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "sast_policies",
        sa.Column("pr_action", sa.String(20), server_default="block", nullable=False),
    )


def downgrade():
    op.drop_column("sast_policies", "pr_action")
