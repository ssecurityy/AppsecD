"""Create dast_learnings table for AI RAG learning database.

Revision ID: 024
Revises: 023
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dast_learnings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("domain", sa.String(255), nullable=False, index=True),
        sa.Column("category", sa.String(50), nullable=False, index=True),
        sa.Column("subcategory", sa.String(100), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("payload_type", sa.String(50), nullable=True),
        sa.Column("target_url", sa.Text(), nullable=True),
        sa.Column("parameter", sa.String(255), nullable=True),
        sa.Column("technology_stack", JSONB(), server_default="{}"),
        sa.Column("evidence", JSONB(), server_default="{}"),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("cwe_id", sa.String(20), nullable=True),
        sa.Column("owasp_ref", sa.String(50), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.8"),
        sa.Column("times_confirmed", sa.Integer(), server_default="1"),
        sa.Column("last_confirmed", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(50), server_default="'claude_scan'"),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_global", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )
    # Composite indexes for RAG queries
    op.create_index("ix_dast_learnings_domain_category", "dast_learnings", ["domain", "category"])
    op.create_index("ix_dast_learnings_org_global", "dast_learnings", ["organization_id", "is_global"])

    # Also add cve_ids column to findings table
    op.add_column("findings", sa.Column("cve_ids", JSONB(), nullable=True, server_default="[]"))


def downgrade():
    op.drop_column("findings", "cve_ids")
    op.drop_index("ix_dast_learnings_org_global")
    op.drop_index("ix_dast_learnings_domain_category")
    op.drop_table("dast_learnings")
