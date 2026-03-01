"""Add JIRA tracking fields to findings and branding fields to organizations.

Revision ID: 015
Revises: 014
"""
from alembic import op
import sqlalchemy as sa


revision = "015"
down_revision = "014"


def upgrade():
    # Add JIRA tracking fields to findings
    op.add_column("findings", sa.Column("jira_key", sa.String(50), nullable=True))
    op.add_column("findings", sa.Column("jira_url", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("jira_status", sa.String(50), nullable=True))

    # Add branding fields to organizations
    op.add_column("organizations", sa.Column("logo_url", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("brand_color", sa.String(20), nullable=True))
    op.add_column("organizations", sa.Column("description", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("findings", "jira_key")
    op.drop_column("findings", "jira_url")
    op.drop_column("findings", "jira_status")
    op.drop_column("organizations", "logo_url")
    op.drop_column("organizations", "brand_color")
    op.drop_column("organizations", "description")
