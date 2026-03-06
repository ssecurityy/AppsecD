"""Add Claude DAST tables: scan sessions, crawl results, usage tracking.

Revision ID: 022
Revises: 021
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "022"
down_revision = "021"


def upgrade() -> None:
    # Claude scan sessions
    op.create_table(
        "claude_scan_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False, unique=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("scan_mode", sa.String(20), server_default="standard"),
        sa.Column("status", sa.String(20), server_default="running"),
        sa.Column("models_used", JSONB, server_default="[]"),
        sa.Column("primary_model", sa.String(64), nullable=True),
        sa.Column("total_input_tokens", sa.Integer(), server_default="0"),
        sa.Column("total_output_tokens", sa.Integer(), server_default="0"),
        sa.Column("total_cached_tokens", sa.Integer(), server_default="0"),
        sa.Column("total_api_calls", sa.Integer(), server_default="0"),
        sa.Column("total_cost_usd", sa.Float(), server_default="0.0"),
        sa.Column("cost_breakdown", JSONB, server_default="{}"),
        sa.Column("phases_completed", JSONB, server_default="[]"),
        sa.Column("current_phase", sa.String(30), nullable=True),
        sa.Column("total_findings", sa.Integer(), server_default="0"),
        sa.Column("findings_by_severity", JSONB, server_default="{}"),
        sa.Column("pages_crawled", sa.Integer(), server_default="0"),
        sa.Column("endpoints_tested", sa.Integer(), server_default="0"),
        sa.Column("new_test_cases", sa.Integer(), server_default="0"),
        sa.Column("pentest_options_offered", sa.Integer(), server_default="0"),
        sa.Column("session_context_key", sa.String(128), nullable=True),
        sa.Column("session_messages_count", sa.Integer(), server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("activity_log", JSONB, server_default="[]"),
        sa.Column("duration_seconds", sa.Integer(), server_default="0"),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_claude_scan_sessions_project_id", "claude_scan_sessions", ["project_id"])
    op.create_index("ix_claude_scan_sessions_scan_id", "claude_scan_sessions", ["scan_id"])

    # Claude crawl results
    op.create_table(
        "claude_crawl_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("crawled_pages", JSONB, server_default="[]"),
        sa.Column("api_endpoints", JSONB, server_default="[]"),
        sa.Column("js_files", JSONB, server_default="[]"),
        sa.Column("subdomains", JSONB, server_default="[]"),
        sa.Column("hidden_paths", JSONB, server_default="[]"),
        sa.Column("hidden_parameters", JSONB, server_default="[]"),
        sa.Column("forms_discovered", JSONB, server_default="[]"),
        sa.Column("technology_stack", JSONB, server_default="{}"),
        sa.Column("attack_surface_summary", sa.Text(), nullable=True),
        sa.Column("sca_results", JSONB, server_default="[]"),
        sa.Column("secrets_found", JSONB, server_default="[]"),
        sa.Column("total_pages", sa.Integer(), server_default="0"),
        sa.Column("total_endpoints", sa.Integer(), server_default="0"),
        sa.Column("total_parameters", sa.Integer(), server_default="0"),
        sa.Column("total_forms", sa.Integer(), server_default="0"),
        sa.Column("total_js_files", sa.Integer(), server_default="0"),
        sa.Column("total_subdomains", sa.Integer(), server_default="0"),
        sa.Column("duration_seconds", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_claude_crawl_results_project_id", "claude_crawl_results", ["project_id"])
    op.create_index("ix_claude_crawl_results_scan_id", "claude_crawl_results", ["scan_id"])

    # Claude usage tracking
    op.create_table(
        "claude_usage_tracking",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("input_tokens", sa.Integer(), server_default="0"),
        sa.Column("output_tokens", sa.Integer(), server_default="0"),
        sa.Column("cached_input_tokens", sa.Integer(), server_default="0"),
        sa.Column("cost_usd", sa.Float(), server_default="0.0"),
        sa.Column("scan_type", sa.String(30), nullable=True),
        sa.Column("phase", sa.String(30), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_claude_usage_tracking_org_id", "claude_usage_tracking", ["organization_id"])
    op.create_index("ix_claude_usage_tracking_project_id", "claude_usage_tracking", ["project_id"])
    op.create_index("ix_claude_usage_tracking_scan_id", "claude_usage_tracking", ["scan_id"])


def downgrade() -> None:
    op.drop_table("claude_usage_tracking")
    op.drop_table("claude_crawl_results")
    op.drop_table("claude_scan_sessions")
