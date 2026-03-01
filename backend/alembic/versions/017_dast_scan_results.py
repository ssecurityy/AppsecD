"""Add dast_scan_results table for persisting scan results.

Revision ID: 017
Revises: 016
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


revision = "017"
down_revision = "016"


def upgrade():
    op.create_table(
        "dast_scan_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), server_default="completed"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("results", JSONB, server_default="[]"),
        sa.Column("passed", sa.Integer(), server_default="0"),
        sa.Column("failed", sa.Integer(), server_default="0"),
        sa.Column("errors_count", sa.Integer(), server_default="0"),
        sa.Column("duration_seconds", sa.Integer(), server_default="0"),
        sa.Column("findings_created", sa.Integer(), server_default="0"),
        sa.Column("finding_titles", JSONB, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
    )
    op.create_index("ix_dast_scan_results_scan_id", "dast_scan_results", ["scan_id"])
    op.create_index("ix_dast_scan_results_project_id", "dast_scan_results", ["project_id"])
    op.create_index("ix_dast_scan_results_project_created", "dast_scan_results", ["project_id", "created_at"])


def downgrade():
    op.drop_index("ix_dast_scan_results_project_created", "dast_scan_results")
    op.drop_index("ix_dast_scan_results_project_id", "dast_scan_results")
    op.drop_index("ix_dast_scan_results_scan_id", "dast_scan_results")
    op.drop_table("dast_scan_results")
