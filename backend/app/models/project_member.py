"""Project member — per-project role and permissions."""
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base

# Project role: viewer (read + report), tester (read + write + report), manager (tester + manage members)
PROJECT_ROLES = ("viewer", "tester", "manager")

ROLE_DEFAULTS = {
    "viewer": {"can_read": True, "can_write": False, "can_download_report": True, "can_manage_members": False},
    "tester": {"can_read": True, "can_write": True, "can_download_report": True, "can_manage_members": False},
    "manager": {"can_read": True, "can_write": True, "can_download_report": True, "can_manage_members": True},
}


def apply_role_defaults(role: str) -> dict:
    return ROLE_DEFAULTS.get(role, ROLE_DEFAULTS["viewer"]).copy()


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # viewer, tester, manager
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=True)  # mark status, add findings
    can_download_report = Column(Boolean, default=True)
    can_manage_members = Column(Boolean, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
