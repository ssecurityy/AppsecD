"""Track phase completions for XP awards — one row per user per project per phase."""
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base


class UserPhaseCompletion(Base):
    __tablename__ = "user_phase_completions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    phase = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
