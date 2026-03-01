"""Stored CVE model for local PostgreSQL CVE cache."""
from sqlalchemy import Column, String, Float, Text, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from datetime import datetime
import uuid
from app.core.database import Base


class StoredCVE(Base):
    __tablename__ = "stored_cves"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(30), unique=True, nullable=False, index=True)
    description = Column(Text)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)
    cwes = Column(JSONB, default=list)
    references = Column(JSONB, default=list)
    published = Column(DateTime, nullable=True, index=True)
    last_modified = Column(DateTime, nullable=True)
    source_data = Column(JSONB, default=dict)  # raw NVD data
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index("ix_stored_cves_severity", "severity"),
        Index("ix_stored_cves_published_desc", published.desc()),
    )
