"""Add findings table

Revision ID: 011
Revises: 010
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("test_result_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.String(10), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=True, server_default="open"),
        sa.Column("owasp_category", sa.String(50), nullable=True),
        sa.Column("cwe_id", sa.String(20), nullable=True),
        sa.Column("affected_url", sa.Text(), nullable=True),
        sa.Column("affected_parameter", sa.Text(), nullable=True),
        sa.Column("request", sa.Text(), nullable=True),
        sa.Column("response", sa.Text(), nullable=True),
        sa.Column("evidence_urls", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("reproduction_steps", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["test_result_id"], ["project_test_results.id"]),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_findings_severity", "findings")
    op.drop_index("ix_findings_project_id", "findings")
    op.drop_table("findings")
