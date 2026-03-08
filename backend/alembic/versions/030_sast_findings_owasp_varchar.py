"""Widen sast_findings.owasp_category to VARCHAR(255) to avoid truncation.

Revision ID: 030_owasp_varchar
Revises: 029_sast_hardening
"""
from alembic import op
import sqlalchemy as sa

revision = "030_owasp_varchar"
down_revision = "029_sast_hardening"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "sast_findings",
        "owasp_category",
        existing_type=sa.String(50),
        type_=sa.String(255),
        existing_nullable=True,
    )


def downgrade():
    op.alter_column(
        "sast_findings",
        "owasp_category",
        existing_type=sa.String(255),
        type_=sa.String(50),
        existing_nullable=True,
    )
