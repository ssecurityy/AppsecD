"""Add Claude AI DAST settings to organizations table.

Revision ID: 023
Revises: 022
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("organizations", sa.Column("claude_enabled", sa.Boolean(), nullable=False, server_default="true"))
    op.add_column("organizations", sa.Column("claude_monthly_budget_usd", sa.Numeric(10, 2), nullable=True))
    op.add_column("organizations", sa.Column("claude_per_scan_limit_usd", sa.Numeric(10, 2), nullable=True, server_default="20.00"))
    op.add_column("organizations", sa.Column("claude_allowed_models", JSONB(), nullable=True, server_default='["claude-haiku-4-5","claude-sonnet-4-6","claude-opus-4-6"]'))
    op.add_column("organizations", sa.Column("claude_max_scans_per_day", sa.Integer(), nullable=True, server_default="50"))
    op.add_column("organizations", sa.Column("claude_deep_scan_approval_required", sa.Boolean(), nullable=False, server_default="true"))
    op.add_column("organizations", sa.Column("claude_dast_api_key", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("organizations", "claude_dast_api_key")
    op.drop_column("organizations", "claude_deep_scan_approval_required")
    op.drop_column("organizations", "claude_max_scans_per_day")
    op.drop_column("organizations", "claude_allowed_models")
    op.drop_column("organizations", "claude_per_scan_limit_usd")
    op.drop_column("organizations", "claude_monthly_budget_usd")
    op.drop_column("organizations", "claude_enabled")
