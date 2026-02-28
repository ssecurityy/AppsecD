"""Add llm_provider support (no schema change - uses existing key-value)

Revision ID: 013
Revises: 012
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # admin_settings uses key-value; llm_provider added via app logic
    pass


def downgrade() -> None:
    pass
