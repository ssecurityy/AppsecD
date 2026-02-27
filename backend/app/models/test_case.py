"""Test case master library model."""
from sqlalchemy import Column, String, Integer, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from datetime import datetime
import uuid
from app.core.database import Base


class TestCase(Base):
    __tablename__ = "test_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    category_id = Column(UUID(as_uuid=True), ForeignKey("categories.id"), nullable=False)
    module_id = Column(String(20), nullable=True)   # MOD-01, MOD-02, etc.
    title = Column(Text, nullable=False)
    description = Column(Text)
    owasp_ref = Column(String(50))
    cwe_id = Column(String(20))
    severity = Column(String(20), default="medium")  # critical, high, medium, low, info
    phase = Column(String(50), nullable=False)
    applicability_conditions = Column(JSONB, default=dict)  # stack conditions
    where_to_test = Column(Text)
    what_to_test = Column(Text)
    how_to_test = Column(Text)
    payloads = Column(JSONB, default=list)
    tool_commands = Column(JSONB, default=list)
    pass_indicators = Column(Text)
    fail_indicators = Column(Text)
    remediation = Column(Text)
    references = Column(JSONB, default=list)
    tags = Column(ARRAY(String), default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
