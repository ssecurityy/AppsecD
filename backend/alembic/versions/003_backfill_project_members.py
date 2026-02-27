"""Backfill project members for existing projects

Revision ID: 003
Revises: 002
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    # Check if projects has created_by or tester_id
    cols = conn.execute(sa.text("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema='public' AND table_name='projects'
        AND column_name IN ('created_by','tester_id')
    """)).fetchall()
    if not cols:
        return
    # Backfill: add project creator/tester as manager for existing projects
    projects = conn.execute(sa.text("""
        SELECT p.id, COALESCE(p.created_by, p.tester_id) as user_id
        FROM projects p
        WHERE NOT EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = p.id)
        AND (p.created_by IS NOT NULL OR p.tester_id IS NOT NULL)
    """)).fetchall()
    for row in projects:
        project_id, user_id = row[0], row[1]
        if user_id:
            conn.execute(sa.text("""
                INSERT INTO project_members (id, project_id, user_id, role, can_read, can_write, can_download_report, can_manage_members, created_at, updated_at)
                VALUES (gen_random_uuid(), :pid, :uid, 'manager', true, true, true, true, now(), now())
                ON CONFLICT ON CONSTRAINT uq_project_member DO NOTHING
            """), {"pid": project_id, "uid": user_id})


def downgrade() -> None:
    pass  # No-op; backfill is additive
