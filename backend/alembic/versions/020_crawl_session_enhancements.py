"""Add deeplinks, js_sca, retire_results, crawler_used to crawl_sessions.

Revision ID: 020
Revises: 019
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "020"
down_revision = "019"


def upgrade() -> None:
    op.add_column("crawl_sessions", sa.Column("deeplinks", JSONB, server_default="[]"))
    op.add_column("crawl_sessions", sa.Column("js_sca", JSONB, nullable=True))
    op.add_column("crawl_sessions", sa.Column("retire_results", JSONB, nullable=True))
    op.add_column("crawl_sessions", sa.Column("crawler_used", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("crawl_sessions", "deeplinks")
    op.drop_column("crawl_sessions", "js_sca")
    op.drop_column("crawl_sessions", "retire_results")
    op.drop_column("crawl_sessions", "crawler_used")
