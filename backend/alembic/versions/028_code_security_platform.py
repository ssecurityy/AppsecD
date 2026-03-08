"""Code security platform: SCA, SBOM, IaC, container, Claude review, DAST scheduling.

Revision ID: 028_code_security
Revises: 027
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "028_code_security"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade():
    # ── Organization — new columns ────────────────────────────────
    op.add_column("organizations", sa.Column("sast_claude_review_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("organizations", sa.Column("sast_pr_review_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("organizations", sa.Column("sast_pr_review_block_on_high", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("organizations", sa.Column("sast_sca_enabled", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("organizations", sa.Column("sast_blocked_licenses", JSONB(), nullable=True))
    op.add_column("organizations", sa.Column("sast_iac_scanning_enabled", sa.Boolean(), server_default="true", nullable=False))

    # ── SastScanSession — new tracking columns ────────────────────
    op.add_column("sast_scan_sessions", sa.Column("claude_review_enabled", sa.Boolean(), server_default="false"))
    op.add_column("sast_scan_sessions", sa.Column("claude_review_cost_usd", sa.Numeric(10, 2), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("claude_review_findings_count", sa.Integer(), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("sca_issues", sa.Integer(), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("iac_issues", sa.Integer(), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("container_issues", sa.Integer(), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("js_deep_issues", sa.Integer(), server_default="0"))
    op.add_column("sast_scan_sessions", sa.Column("license_issues", sa.Integer(), server_default="0"))

    # ── SastPolicy — extended policy fields ───────────────────────
    op.add_column("sast_policies", sa.Column("fail_on_sca_critical", sa.Boolean(), server_default="true"))
    op.add_column("sast_policies", sa.Column("fail_on_kev", sa.Boolean(), server_default="true"))
    op.add_column("sast_policies", sa.Column("max_dependency_issues", sa.Integer(), server_default="-1"))
    op.add_column("sast_policies", sa.Column("blocked_licenses", JSONB(), nullable=True))
    op.add_column("sast_policies", sa.Column("fail_on_iac_critical", sa.Boolean(), server_default="true"))
    op.add_column("sast_policies", sa.Column("fail_on_container_critical", sa.Boolean(), server_default="true"))

    # ── New table: sast_dependencies ──────────────────────────────
    op.create_table(
        "sast_dependencies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("ecosystem", sa.String(50), nullable=False),  # npm, pypi, go, maven, cargo, rubygems, nuget, packagist
        sa.Column("manifest_file", sa.String(500), nullable=True),
        sa.Column("latest_version", sa.String(100), nullable=True),
        sa.Column("is_outdated", sa.Boolean(), server_default="false"),
        sa.Column("is_direct", sa.Boolean(), server_default="true"),
        sa.Column("license_id", sa.String(100), nullable=True),  # SPDX identifier
        sa.Column("license_risk", sa.String(20), nullable=True),  # high, medium, low, unknown
        sa.Column("vulnerabilities", JSONB(), nullable=True),  # [{osv_id, cvss, severity, summary, fixed_version}]
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("in_kev", sa.Boolean(), server_default="false"),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True, index=True),
        sa.Column("status", sa.String(30), server_default="open"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    # ── New table: sast_sboms ─────────────────────────────────────
    op.create_table(
        "sast_sboms",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),  # cyclonedx, spdx
        sa.Column("spec_version", sa.String(20), nullable=False),  # 1.5, 2.3
        sa.Column("component_count", sa.Integer(), server_default="0"),
        sa.Column("total_dependencies", sa.Integer(), server_default="0"),
        sa.Column("sbom_data", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    # ── New table: dast_schedules ─────────────────────────────────
    op.create_table(
        "dast_schedules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("scan_config", JSONB(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    # ── New table: dast_baselines ─────────────────────────────────
    op.create_table(
        "dast_baselines",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_session_id", sa.String(100), nullable=True),
        sa.Column("total_findings", sa.Integer(), server_default="0"),
        sa.Column("findings_by_severity", JSONB(), nullable=True),
        sa.Column("findings_snapshot", JSONB(), nullable=True),
        sa.Column("new_findings", sa.Integer(), server_default="0"),
        sa.Column("fixed_findings", sa.Integer(), server_default="0"),
        sa.Column("unchanged_findings", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade():
    # ── Drop new tables (reverse order) ───────────────────────────
    op.drop_table("dast_baselines")
    op.drop_table("dast_schedules")
    op.drop_table("sast_sboms")
    op.drop_table("sast_dependencies")

    # ── Remove SastPolicy extended columns ────────────────────────
    op.drop_column("sast_policies", "fail_on_container_critical")
    op.drop_column("sast_policies", "fail_on_iac_critical")
    op.drop_column("sast_policies", "blocked_licenses")
    op.drop_column("sast_policies", "max_dependency_issues")
    op.drop_column("sast_policies", "fail_on_kev")
    op.drop_column("sast_policies", "fail_on_sca_critical")

    # ── Remove SastScanSession tracking columns ───────────────────
    op.drop_column("sast_scan_sessions", "license_issues")
    op.drop_column("sast_scan_sessions", "js_deep_issues")
    op.drop_column("sast_scan_sessions", "container_issues")
    op.drop_column("sast_scan_sessions", "iac_issues")
    op.drop_column("sast_scan_sessions", "sca_issues")
    op.drop_column("sast_scan_sessions", "claude_review_findings_count")
    op.drop_column("sast_scan_sessions", "claude_review_cost_usd")
    op.drop_column("sast_scan_sessions", "claude_review_enabled")

    # ── Remove Organization columns ──────────────────────────────
    op.drop_column("organizations", "sast_iac_scanning_enabled")
    op.drop_column("organizations", "sast_blocked_licenses")
    op.drop_column("organizations", "sast_sca_enabled")
    op.drop_column("organizations", "sast_pr_review_block_on_high")
    op.drop_column("organizations", "sast_pr_review_enabled")
    op.drop_column("organizations", "sast_claude_review_enabled")
