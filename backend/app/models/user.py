"""User model."""
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Date, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime, date
import uuid
from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(20), default="tester")  # admin, lead, tester, viewer
    is_active = Column(Boolean, default=True)
    xp_points = Column(Integer, default=0)
    level = Column(Integer, default=1)
    badges = Column(JSONB, default=list)
    last_login = Column(DateTime, nullable=True)
    streak_days = Column(Integer, default=0)
    last_streak_date = Column(Date, nullable=True)
    last_finding_date = Column(Date, nullable=True)
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
