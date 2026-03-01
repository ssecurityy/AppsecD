"""Add ai_report_content to projects for persisting AI summaries.

Revision ID: 018
Revises: 017
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "018"
down_revision = "017"


def upgrade():
    op.add_column("projects", sa.Column("ai_report_content", JSONB, nullable=True))


def downgrade():
    op.drop_column("projects", "ai_report_content")
