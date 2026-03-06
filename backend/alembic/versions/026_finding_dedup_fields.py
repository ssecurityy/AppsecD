"""Add dedup fingerprint, last_seen_at, scan_count to findings.

Revision ID: 026
Revises: 025
"""
from alembic import op
import sqlalchemy as sa

revision = "026"
down_revision = "025"


def upgrade():
    op.add_column("findings", sa.Column("dedup_fingerprint", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(), nullable=True))
    op.add_column("findings", sa.Column("scan_count", sa.Integer(), server_default="1", nullable=True))
    op.create_index("ix_findings_dedup_fingerprint", "findings", ["dedup_fingerprint"])


def downgrade():
    op.drop_index("ix_findings_dedup_fingerprint", table_name="findings")
    op.drop_column("findings", "scan_count")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "dedup_fingerprint")
