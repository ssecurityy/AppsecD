"""Security finding model with vulnerability management."""
from sqlalchemy import Column, String, Text, DateTime, Date, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from datetime import datetime
import uuid
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    include_in_report = Column(Boolean, default=True, nullable=False)  # Toggle for report inclusion (DAST/manual)
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

    # JIRA integration fields
    jira_key = Column(String(50), nullable=True)  # e.g., PROJ-123
    jira_url = Column(Text, nullable=True)  # e.g., https://org.atlassian.net/browse/PROJ-123
    jira_status = Column(String(50), nullable=True)  # e.g., Open, In Progress, Done

    # Vulnerability Management / Recheck fields
    recheck_status = Column(String(30), default="pending")
    # pending, resolved, not_fixed, partially_fixed, exception, deferred, retest_needed
    recheck_notes = Column(Text, nullable=True)
    recheck_date = Column(DateTime, nullable=True)
    recheck_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    recheck_evidence = Column(JSONB, default=list)  # [{filename, url}]
    original_severity = Column(String(20), nullable=True)  # preserve original severity
    recheck_count = Column(Integer, default=0)  # how many times rechecked
    remediation_deadline = Column(Date, nullable=True)
    remediation_owner = Column(Text, nullable=True)  # dev team / person responsible
    recheck_history = Column(JSONB, default=list)  # [{date, status, notes, by}]
