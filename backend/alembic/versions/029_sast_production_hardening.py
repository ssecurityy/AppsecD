"""SAST production hardening: finding lifecycle, custom rules, trend analytics, reachability.

Revision ID: 029_sast_hardening
Revises: 028_code_security
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "029_sast_hardening"
down_revision = "028_code_security"
branch_labels = None
depends_on = None


def upgrade():
    # ── SastFinding — lifecycle management columns ─────────────────
    op.add_column("sast_findings", sa.Column("assigned_to", UUID(as_uuid=True), nullable=True))
    op.add_column("sast_findings", sa.Column("sla_deadline", sa.DateTime(), nullable=True))
    op.add_column("sast_findings", sa.Column("exception_approved_by", UUID(as_uuid=True), nullable=True))
    op.add_column("sast_findings", sa.Column("exception_expires_at", sa.DateTime(), nullable=True))
    op.add_column("sast_findings", sa.Column("status_history", JSONB(), nullable=True))
    op.add_column("sast_findings", sa.Column("is_reachable", sa.Boolean(), server_default="true", nullable=True))
    op.add_column("sast_findings", sa.Column("is_suppressed", sa.Boolean(), server_default="false", nullable=True))
    op.add_column("sast_findings", sa.Column("suppression_reason", sa.Text(), nullable=True))
    op.add_column("sast_findings", sa.Column("suppression_type", sa.String(30), nullable=True))

    op.create_index("ix_sast_findings_assigned_to", "sast_findings", ["assigned_to"])
    op.create_index("ix_sast_findings_sla_deadline", "sast_findings", ["sla_deadline"])

    # ── Organization — additional enterprise controls ──────────────
    op.add_column("organizations", sa.Column("sast_custom_exclusion_patterns", JSONB(), nullable=True))
    op.add_column("organizations", sa.Column("sast_confidence_threshold", sa.Float(), server_default="0.7", nullable=True))
    op.add_column("organizations", sa.Column("sast_sla_policy", JSONB(), nullable=True,
                                              server_default='{"critical": 1, "high": 3, "medium": 7, "low": 30, "info": 90}'))
    op.add_column("organizations", sa.Column("sast_custom_instructions", sa.Text(), nullable=True))

    # ── Custom Rules table ─────────────────────────────────────────
    op.create_table(
        "sast_custom_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rule_yaml", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_sast_custom_rules_org_id", "sast_custom_rules", ["organization_id"])

    # ── Trend Snapshots table ──────────────────────────────────────
    op.create_table(
        "sast_trend_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("total_issues", sa.Integer(), server_default="0"),
        sa.Column("new_issues", sa.Integer(), server_default="0"),
        sa.Column("fixed_issues", sa.Integer(), server_default="0"),
        sa.Column("issues_by_severity", JSONB(), nullable=True),
        sa.Column("issues_by_scanner", JSONB(), nullable=True),
        sa.Column("mttr_hours", sa.Float(), nullable=True),
        sa.Column("fix_rate_pct", sa.Float(), nullable=True),
        sa.Column("issues_per_kloc", sa.Float(), nullable=True),
        sa.Column("metrics", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_sast_trend_snapshots_project", "sast_trend_snapshots", ["project_id"])
    op.create_index("ix_sast_trend_snapshots_created", "sast_trend_snapshots", ["created_at"])

    # ── Supply Chain Alerts table ──────────────────────────────────
    op.create_table(
        "sast_supply_chain_alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_type", sa.String(50), nullable=False),  # typosquatting, malicious, dependency_confusion
        sa.Column("package_name", sa.String(500), nullable=False),
        sa.Column("package_version", sa.String(100), nullable=True),
        sa.Column("ecosystem", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("similar_to", sa.String(500), nullable=True),  # For typosquatting: the legitimate package
        sa.Column("evidence", JSONB(), nullable=True),
        sa.Column("status", sa.String(30), server_default="open"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_sast_supply_chain_alerts_scan", "sast_supply_chain_alerts", ["scan_session_id"])
    op.create_index("ix_sast_supply_chain_alerts_project", "sast_supply_chain_alerts", ["project_id"])


def downgrade():
    # Drop new tables
    op.drop_table("sast_supply_chain_alerts")
    op.drop_table("sast_trend_snapshots")
    op.drop_table("sast_custom_rules")

    # Drop organization columns
    op.drop_column("organizations", "sast_custom_instructions")
    op.drop_column("organizations", "sast_sla_policy")
    op.drop_column("organizations", "sast_confidence_threshold")
    op.drop_column("organizations", "sast_custom_exclusion_patterns")

    # Drop finding lifecycle columns
    op.drop_index("ix_sast_findings_sla_deadline", table_name="sast_findings")
    op.drop_index("ix_sast_findings_assigned_to", table_name="sast_findings")
    op.drop_column("sast_findings", "suppression_type")
    op.drop_column("sast_findings", "suppression_reason")
    op.drop_column("sast_findings", "is_suppressed")
    op.drop_column("sast_findings", "is_reachable")
    op.drop_column("sast_findings", "status_history")
    op.drop_column("sast_findings", "exception_expires_at")
    op.drop_column("sast_findings", "exception_approved_by")
    op.drop_column("sast_findings", "sla_deadline")
    op.drop_column("sast_findings", "assigned_to")
