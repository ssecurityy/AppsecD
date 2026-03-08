"""DAST AI Learning model — stores past scan learnings for RAG retrieval."""
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer, Float, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class DastLearning(Base):
    __tablename__ = "dast_learnings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)  # sqli, xss, auth, ssrf, waf_bypass
    subcategory = Column(String(100), nullable=True)  # time_based, reflected, cloudflare_bypass
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)  # The actual payload that worked
    payload_type = Column(String(50), nullable=True)  # successful_attack, waf_bypass, false_positive
    target_url = Column(Text, nullable=True)
    parameter = Column(String(255), nullable=True)
    technology_stack = Column(JSONB, default=dict)  # {"server":"nginx","framework":"laravel","waf":"cloudflare"}
    evidence = Column(JSONB, default=dict)  # {request, response, status_code, detection_method}
    severity = Column(String(20), nullable=True)
    cwe_id = Column(String(20), nullable=True)
    owasp_ref = Column(String(50), nullable=True)
    confidence = Column(Float, default=0.8)
    times_confirmed = Column(Integer, default=1)
    last_confirmed = Column(DateTime, nullable=True)
    source = Column(String(50), default="claude_scan")  # claude_scan, deterministic, manual
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    is_global = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
