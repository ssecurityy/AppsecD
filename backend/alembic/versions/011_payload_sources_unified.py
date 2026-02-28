"""Add payload_sources and wordlist_source_files for FuzzDB, BLNS, XSS, SQLi, NoSQL, etc.

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
        "payload_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("repo_url", sa.String(500), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("order_index", sa.Integer(), nullable=True),
        sa.Column("synced_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_payload_sources_slug", "payload_sources", ["slug"], unique=True)

    op.create_table(
        "wordlist_source_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category_path", sa.String(500), nullable=False),
        sa.Column("path", sa.String(500), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["source_id"], ["payload_sources.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_wordlist_source_files_source", "wordlist_source_files", ["source_id"])
    op.create_index("ix_wordlist_source_files_path", "wordlist_source_files", ["source_id", "path"], unique=True)


def downgrade() -> None:
    op.drop_table("wordlist_source_files")
    op.drop_table("payload_sources")
