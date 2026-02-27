"""Project test result model — per test case per project."""
from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class ProjectTestResult(Base):
    __tablename__ = "project_test_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    test_case_id = Column(UUID(as_uuid=True), ForeignKey("test_cases.id"), nullable=False)
    tester_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    # Status: not_started, in_progress, passed, failed, na, blocked
    status = Column(String(20), default="not_started")
    is_applicable = Column(Boolean, default=True)
    severity_override = Column(String(20), nullable=True)
    notes = Column(Text)
    evidence = Column(JSONB, default=list)   # [{filename, url, description}]
    request_captured = Column(Text)
    response_captured = Column(Text)
    reproduction_steps = Column(Text)
    tool_used = Column(Text)
    payload_used = Column(Text)
    time_spent_seconds = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
