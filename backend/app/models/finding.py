"""Security finding model."""
from sqlalchemy import Column, String, Text, DateTime, Date, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from datetime import datetime
import uuid
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    test_result_id = Column(UUID(as_uuid=True), ForeignKey("project_test_results.id"), nullable=True)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    cvss_score = Column(String(10), nullable=True)
    cvss_vector = Column(Text, nullable=True)
    # Status: open, confirmed, mitigated, fixed, accepted_risk, fp
    status = Column(String(20), default="open")
    owasp_category = Column(String(50))
    cwe_id = Column(String(20))
    affected_url = Column(Text)
    affected_parameter = Column(Text)
    request = Column(Text)
    response = Column(Text)
    evidence_urls = Column(ARRAY(String), default=list)
    reproduction_steps = Column(Text)
    impact = Column(Text)
    recommendation = Column(Text)
    references = Column(JSONB, default=list)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    due_date = Column(Date, nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
