"""Add onboarding fields: testing_scope, target_completion_date, classification

Revision ID: 004
Revises: 003
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("projects", sa.Column("testing_scope", sa.Text(), nullable=True))
    op.add_column("projects", sa.Column("target_completion_date", sa.Date(), nullable=True))
    op.add_column("projects", sa.Column("classification", sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column("projects", "classification")
    op.drop_column("projects", "target_completion_date")
    op.drop_column("projects", "testing_scope")
