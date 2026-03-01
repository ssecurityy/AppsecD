"""DAST scan result - persisted for when user returns after scan runs in background."""
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class DastScanResult(Base):
    __tablename__ = "dast_scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(String(64), nullable=False, index=True)
    target_url = Column(Text, nullable=False)
    status = Column(String(20), default="completed")  # completed, error
    error = Column(Text, nullable=True)
    results = Column(JSONB, default=list)  # list of check result dicts
    passed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)
    duration_seconds = Column(Integer, default=0)
    findings_created = Column(Integer, default=0)
    finding_titles = Column(JSONB, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
