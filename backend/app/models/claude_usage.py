"""Claude usage tracking — per-call cost tracking for enterprise controls."""
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Float
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base


class ClaudeUsageTracking(Base):
    __tablename__ = "claude_usage_tracking"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_id = Column(String(64), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Token usage
    model = Column(String(64), nullable=False)  # claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-6
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    cached_input_tokens = Column(Integer, default=0)

    # Cost
    cost_usd = Column(Float, default=0.0)

    # Metadata
    scan_type = Column(String(30), nullable=True)  # full_scan, retest, crawl_only, generate_checks
    phase = Column(String(30), nullable=True)  # crawling, recon, automated_checks, dynamic_testing, etc.

    created_at = Column(DateTime, default=datetime.utcnow)
