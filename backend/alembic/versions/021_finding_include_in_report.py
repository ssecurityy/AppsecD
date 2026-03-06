"""Add include_in_report to findings for report visibility toggle.

Revision ID: 021
Revises: 020
"""
from alembic import op
import sqlalchemy as sa

revision = "021"
down_revision = "020"


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("include_in_report", sa.Boolean(), server_default=sa.true(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("findings", "include_in_report")
