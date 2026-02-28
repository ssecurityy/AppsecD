"""Payload and SecLists tables - 100% PostgreSQL, no filesystem dependency

Revision ID: 010
Revises: 009
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "payload_categories",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("order_index", sa.Integer(), nullable=True),
        sa.Column("has_readme", sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_payload_categories_slug", "payload_categories", ["slug"], unique=True)

    op.create_table(
        "payload_contents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["category_id"], ["payload_categories.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_payload_contents_category", "payload_contents", ["category_id"])

    op.create_table(
        "seclist_categories",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("order_index", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_seclist_categories_slug", "seclist_categories", ["slug"], unique=True)

    op.create_table(
        "seclist_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("path", sa.String(500), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["category_id"], ["seclist_categories.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_seclist_files_category", "seclist_files", ["category_id"])
    op.create_index("ix_seclist_files_path", "seclist_files", ["category_id", "path"], unique=True)


def downgrade() -> None:
    op.drop_table("seclist_files")
    op.drop_table("seclist_categories")
    op.drop_table("payload_contents")
    op.drop_table("payload_categories")
