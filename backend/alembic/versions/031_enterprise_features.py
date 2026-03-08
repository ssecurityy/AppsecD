"""Enterprise features: notifications, suppression rules, dataflow paths, SAML/OIDC.

Revision ID: 031_enterprise
Revises: 030_owasp_varchar
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "031_enterprise"
down_revision = "030_owasp_varchar"
branch_labels = None
depends_on = None


def upgrade():
    # ── Notifications table ───────────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", UUID(as_uuid=True), nullable=True),
        sa.Column("is_read", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_notifications_org_user_read", "notifications", ["organization_id", "user_id", "is_read"])

    # ── SAST suppression rules ─────────────────────────────────────
    op.create_table(
        "sast_suppression_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("rule_type", sa.String(30), nullable=False),
        sa.Column("pattern", sa.String(500), nullable=False),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("approved_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_sast_suppression_rules_org", "sast_suppression_rules", ["organization_id"])

    # ── SAST dataflow paths (taint analysis) ───────────────────────
    op.create_table(
        "sast_dataflow_paths",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_session_id", UUID(as_uuid=True), sa.ForeignKey("sast_scan_sessions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("sast_findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_file", sa.String(500), nullable=True),
        sa.Column("source_line", sa.Integer(), nullable=True),
        sa.Column("source_type", sa.String(100), nullable=True),
        sa.Column("sink_file", sa.String(500), nullable=True),
        sa.Column("sink_line", sa.Integer(), nullable=True),
        sa.Column("sink_type", sa.String(100), nullable=True),
        sa.Column("path_nodes", JSONB(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_sast_dataflow_paths_finding", "sast_dataflow_paths", ["finding_id"])

    # ── Organizations: SAML columns ───────────────────────────────
    op.add_column("organizations", sa.Column("saml_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("organizations", sa.Column("saml_entity_id", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("saml_sso_url", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("saml_certificate", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("saml_attribute_mapping", JSONB(), nullable=True))

    # ── Organizations: OAuth2/OIDC columns ─────────────────────────
    op.add_column("organizations", sa.Column("oidc_client_id", sa.String(255), nullable=True))
    op.add_column("organizations", sa.Column("oidc_client_secret", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("oidc_issuer_url", sa.String(500), nullable=True))
    op.add_column("organizations", sa.Column("oidc_scopes", sa.String(500), nullable=True))


def downgrade():
    op.drop_column("organizations", "oidc_scopes")
    op.drop_column("organizations", "oidc_issuer_url")
    op.drop_column("organizations", "oidc_client_secret")
    op.drop_column("organizations", "oidc_client_id")
    op.drop_column("organizations", "saml_attribute_mapping")
    op.drop_column("organizations", "saml_certificate")
    op.drop_column("organizations", "saml_sso_url")
    op.drop_column("organizations", "saml_entity_id")
    op.drop_column("organizations", "saml_enabled")
    op.drop_table("sast_dataflow_paths")
    op.drop_table("sast_suppression_rules")
    op.drop_table("notifications")
