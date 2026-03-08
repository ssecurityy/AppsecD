"""Create SAST tables and add SAST org columns.

Revision ID: 027
Revises: 026
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def upgrade():
    # ── SAST Scan Sessions ─────────────────────────────────────────
    op.create_table(
        "sast_scan_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_type", sa.String(30), nullable=False, server_default="zip_upload"),
        sa.Column("status", sa.String(30), nullable=False, server_default="queued", index=True),
        sa.Column("source_info", JSONB(), nullable=True),
        sa.Column("language_stats", JSONB(), nullable=True),
        sa.Column("total_files", sa.Integer(), server_default="0"),
        sa.Column("files_scanned", sa.Integer(), server_default="0"),
        sa.Column("total_issues", sa.Integer(), server_default="0"),
        sa.Column("issues_by_severity", JSONB(), nullable=True),
        sa.Column("issues_by_category", JSONB(), nullable=True),
        sa.Column("ai_analysis_enabled", sa.Boolean(), server_default="false"),
        sa.Column("ai_cost_usd", sa.Numeric(10, 2), server_default="0"),
        sa.Column("ai_model_used", sa.String(50), nullable=True),
        sa.Column("semgrep_rules_used", sa.Integer(), server_default="0"),
        sa.Column("custom_rules_used", sa.Integer(), server_default="0"),
        sa.Column("secrets_found", sa.Integer(), server_default="0"),
        sa.Column("dependency_issues", sa.Integer(), server_default="0"),
        sa.Column("scan_duration_seconds", sa.Float(), nullable=True),
        sa.Column("scan_config", JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("sarif_output", JSONB(), nullable=True),
        sa.Column("policy_result", JSONB(), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), index=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )

    # ── SAST Findings ──────────────────────────────────────────────
    op.create_table(
        "sast_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("rule_source", sa.String(30), server_default="semgrep"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium", index=True),
        sa.Column("confidence", sa.String(20), server_default="medium"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("file_path", sa.String(1000), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("column_start", sa.Integer(), nullable=True),
        sa.Column("column_end", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("fix_suggestion", sa.Text(), nullable=True),
        sa.Column("fixed_code", sa.Text(), nullable=True),
        sa.Column("ai_analysis", JSONB(), nullable=True),
        sa.Column("cwe_id", sa.String(20), nullable=True),
        sa.Column("owasp_category", sa.String(50), nullable=True),
        sa.Column("references", JSONB(), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True, index=True),
        sa.Column("status", sa.String(30), server_default="open", index=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # ── SAST Repositories ─────────────────────────────────────────
    op.create_table(
        "sast_repositories",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("provider", sa.String(30), nullable=False, server_default="github"),
        sa.Column("repo_url", sa.String(500), nullable=False),
        sa.Column("repo_name", sa.String(255), nullable=False),
        sa.Column("repo_owner", sa.String(255), nullable=True),
        sa.Column("default_branch", sa.String(100), server_default="main"),
        sa.Column("access_token_encrypted", sa.Text(), nullable=True),
        sa.Column("webhook_id", sa.String(100), nullable=True),
        sa.Column("webhook_secret", sa.String(64), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        sa.Column("auto_scan_enabled", sa.Boolean(), server_default="false"),
        sa.Column("auto_scan_branches", JSONB(), server_default='["main"]'),
        sa.Column("scan_config", JSONB(), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # ── SAST Policies ──────────────────────────────────────────────
    op.create_table(
        "sast_policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_default", sa.Boolean(), server_default="false"),
        sa.Column("severity_threshold", sa.String(20), server_default="critical"),
        sa.Column("max_issues_allowed", sa.Integer(), server_default="-1"),
        sa.Column("fail_on_secrets", sa.Boolean(), server_default="true"),
        sa.Column("required_fix_categories", JSONB(), nullable=True),
        sa.Column("exclude_rules", JSONB(), nullable=True),
        sa.Column("compliance_standards", JSONB(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # ── Organization SAST columns ──────────────────────────────────
    op.add_column("organizations", sa.Column("sast_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("organizations", sa.Column("sast_monthly_budget_usd", sa.Numeric(10, 2), nullable=True))
    op.add_column("organizations", sa.Column("sast_max_scans_per_day", sa.Integer(), server_default="20", nullable=True))
    op.add_column("organizations", sa.Column("sast_ai_analysis_enabled", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("organizations", sa.Column("sast_github_app_installation_id", sa.String(100), nullable=True))


def downgrade():
    op.drop_column("organizations", "sast_github_app_installation_id")
    op.drop_column("organizations", "sast_ai_analysis_enabled")
    op.drop_column("organizations", "sast_max_scans_per_day")
    op.drop_column("organizations", "sast_monthly_budget_usd")
    op.drop_column("organizations", "sast_enabled")
    op.drop_table("sast_policies")
    op.drop_table("sast_repositories")
    op.drop_table("sast_findings")
    op.drop_table("sast_scan_sessions")
