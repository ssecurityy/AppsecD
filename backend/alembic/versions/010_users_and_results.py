"""Add users table, project_test_results table, and missing project/test_case columns

Revision ID: 010
Revises: 009
Create Date: 2026-02-27

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=True, server_default="tester"),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column("xp_points", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("level", sa.Integer(), nullable=True, server_default="1"),
        sa.Column("badges", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.Column("streak_days", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("last_streak_date", sa.Date(), nullable=True),
        sa.Column("last_finding_date", sa.Date(), nullable=True),
        sa.Column("mfa_secret", sa.String(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=True, server_default="false"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.add_column("projects", sa.Column("tester_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("projects", sa.Column("lead_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("projects", sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("projects", sa.Column("testing_type", sa.String(20), nullable=True, server_default="grey_box"))
    op.add_column("projects", sa.Column("environment", sa.String(20), nullable=True, server_default="staging"))
    op.add_column("projects", sa.Column("applicable_categories", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("projects", sa.Column("risk_rating", sa.String(20), nullable=True, server_default="medium"))
    op.add_column("projects", sa.Column("started_at", sa.DateTime(), nullable=True))
    op.add_column("projects", sa.Column("completed_at", sa.DateTime(), nullable=True))
    op.create_foreign_key("fk_projects_tester", "projects", "users", ["tester_id"], ["id"])
    op.create_foreign_key("fk_projects_lead", "projects", "users", ["lead_id"], ["id"])
    op.create_foreign_key("fk_projects_created_by", "projects", "users", ["created_by"], ["id"])

    op.add_column("test_cases", sa.Column("module_id", sa.String(20), nullable=True))
    op.add_column("test_cases", sa.Column("applicability_conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=True))

    op.create_table(
        "project_test_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("test_case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tester_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=True, server_default="not_started"),
        sa.Column("is_applicable", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column("severity_override", sa.String(20), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("request_captured", sa.Text(), nullable=True),
        sa.Column("response_captured", sa.Text(), nullable=True),
        sa.Column("reproduction_steps", sa.Text(), nullable=True),
        sa.Column("tool_used", sa.Text(), nullable=True),
        sa.Column("payload_used", sa.Text(), nullable=True),
        sa.Column("time_spent_seconds", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["test_case_id"], ["test_cases.id"]),
        sa.ForeignKeyConstraint(["tester_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("project_test_results")
    op.drop_column("test_cases", "applicability_conditions")
    op.drop_column("test_cases", "module_id")
    op.drop_constraint("fk_projects_created_by", "projects", type_="foreignkey")
    op.drop_constraint("fk_projects_lead", "projects", type_="foreignkey")
    op.drop_constraint("fk_projects_tester", "projects", type_="foreignkey")
    op.drop_column("projects", "completed_at")
    op.drop_column("projects", "started_at")
    op.drop_column("projects", "risk_rating")
    op.drop_column("projects", "applicable_categories")
    op.drop_column("projects", "environment")
    op.drop_column("projects", "testing_type")
    op.drop_column("projects", "created_by")
    op.drop_column("projects", "lead_id")
    op.drop_column("projects", "tester_id")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
