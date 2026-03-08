"""SAST scan stats: files_skipped, skip_reasons, lines_of_code.

Revision ID: 032_scan_stats
Revises: 031_enterprise
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "032_scan_stats"
down_revision = "031_enterprise"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sast_scan_sessions", sa.Column("files_skipped", sa.Integer(), server_default="0", nullable=False))
    op.add_column("sast_scan_sessions", sa.Column("skip_reasons", JSONB(), nullable=True))
    op.add_column("sast_scan_sessions", sa.Column("lines_of_code", JSONB(), nullable=True))


def downgrade():
    op.drop_column("sast_scan_sessions", "lines_of_code")
    op.drop_column("sast_scan_sessions", "skip_reasons")
    op.drop_column("sast_scan_sessions", "files_skipped")
