"""Add stored_cves table and org_feature_flags table.

Revision ID: 016
Revises: 015
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


revision = "016"
down_revision = "015"


def upgrade():
    # Stored CVEs table
    op.create_table(
        "stored_cves",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", sa.String(30), unique=True, nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("cwes", JSONB, server_default="[]"),
        sa.Column("references", JSONB, server_default="[]"),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("source_data", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_stored_cves_cve_id", "stored_cves", ["cve_id"])
    op.create_index("ix_stored_cves_severity", "stored_cves", ["severity"])
    op.create_index("ix_stored_cves_published_desc", "stored_cves", [sa.text("published DESC")])

    # Org feature flags table
    op.create_table(
        "org_feature_flags",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feature_key", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true"),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "feature_key", name="uq_org_feature_flag"),
    )


def downgrade():
    op.drop_table("org_feature_flags")
    op.drop_index("ix_stored_cves_published_desc", "stored_cves")
    op.drop_index("ix_stored_cves_severity", "stored_cves")
    op.drop_index("ix_stored_cves_cve_id", "stored_cves")
    op.drop_table("stored_cves")
