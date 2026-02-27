"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "categories",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("icon", sa.String(50), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("order_index", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_categories_slug", "categories", ["slug"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("application_name", sa.String(255), nullable=False),
        sa.Column("application_version", sa.String(50), nullable=True),
        sa.Column("application_url", sa.Text(), nullable=False),
        sa.Column("app_owner_name", sa.String(255), nullable=True),
        sa.Column("app_spoc_name", sa.String(255), nullable=True),
        sa.Column("app_spoc_email", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("stack_profile", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("total_test_cases", sa.Integer(), nullable=True),
        sa.Column("tested_count", sa.Integer(), nullable=True),
        sa.Column("passed_count", sa.Integer(), nullable=True),
        sa.Column("failed_count", sa.Integer(), nullable=True),
        sa.Column("na_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "test_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owasp_ref", sa.String(50), nullable=True),
        sa.Column("cwe_id", sa.String(20), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("where_to_test", sa.Text(), nullable=True),
        sa.Column("what_to_test", sa.Text(), nullable=True),
        sa.Column("how_to_test", sa.Text(), nullable=True),
        sa.Column("payloads", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("tool_commands", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("pass_indicators", sa.Text(), nullable=True),
        sa.Column("fail_indicators", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["category_id"], ["categories.id"], ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("test_cases")
    op.drop_table("projects")
    op.drop_index("ix_categories_slug", table_name="categories")
    op.drop_table("categories")
