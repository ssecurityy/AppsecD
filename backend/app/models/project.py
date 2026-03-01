"""Project model."""
from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey, Date
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    name = Column(String(255), nullable=False)
    application_name = Column(String(255), nullable=False)
    application_version = Column(String(50))
    application_url = Column(Text, nullable=False)
    app_owner_name = Column(String(255))
    app_spoc_name = Column(String(255))
    app_spoc_email = Column(String(255))
    tester_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    lead_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    status = Column(String(20), default="draft")  # draft, in_progress, review, completed, archived
    testing_type = Column(String(20), default="grey_box")  # black_box, grey_box, white_box
    environment = Column(String(20), default="staging")
    testing_scope = Column(Text, nullable=True)  # URLs in scope, exclusions
    target_completion_date = Column(Date, nullable=True)
    classification = Column(String(20), nullable=True)  # internal, confidential, public
    stack_profile = Column(JSONB, default=dict)
    applicable_categories = Column(JSONB, default=list)
    total_test_cases = Column(Integer, default=0)
    tested_count = Column(Integer, default=0)
    passed_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    na_count = Column(Integer, default=0)
    risk_rating = Column(String(20), default="medium")
    ai_report_content = Column(JSONB, nullable=True)  # executive_summary, technical_summary, strategic_recommendations, ai_summary, risk_rating, key_statistics
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
