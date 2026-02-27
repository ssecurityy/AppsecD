"""Add streak and daily bonus tracking to users

Revision ID: 006
Revises: 005
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("streak_days", sa.Integer(), nullable=True, server_default="0"))
    op.add_column("users", sa.Column("last_streak_date", sa.Date(), nullable=True))
    op.add_column("users", sa.Column("last_finding_date", sa.Date(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "last_finding_date")
    op.drop_column("users", "last_streak_date")
    op.drop_column("users", "streak_days")
