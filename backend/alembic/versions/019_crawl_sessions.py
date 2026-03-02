"""Add crawl_sessions table for spider/crawler results.

Revision ID: 019
Revises: 018
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "019"
down_revision = "018"


def upgrade() -> None:
    op.create_table(
        "crawl_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("crawl_id", sa.String(64), nullable=False, index=True),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), server_default="running"),
        sa.Column("crawl_type", sa.String(20), server_default="full"),
        sa.Column("auth_type", sa.String(20), nullable=True),
        sa.Column("urls", JSONB, server_default="[]"),
        sa.Column("api_endpoints", JSONB, server_default="[]"),
        sa.Column("parameters", JSONB, server_default="[]"),
        sa.Column("forms", JSONB, server_default="[]"),
        sa.Column("js_files", JSONB, server_default="[]"),
        sa.Column("pages", JSONB, server_default="[]"),
        sa.Column("total_urls", sa.Integer, server_default="0"),
        sa.Column("total_endpoints", sa.Integer, server_default="0"),
        sa.Column("total_parameters", sa.Integer, server_default="0"),
        sa.Column("total_forms", sa.Integer, server_default="0"),
        sa.Column("total_js_files", sa.Integer, server_default="0"),
        sa.Column("duration_seconds", sa.Integer, server_default="0"),
        sa.Column("max_depth", sa.Integer, server_default="3"),
        sa.Column("crawl_scope", sa.String(20), server_default="host"),
        sa.Column("directory_tree", JSONB, server_default="[]"),
        sa.Column("directory_flat", JSONB, server_default="[]"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("crawl_sessions")
