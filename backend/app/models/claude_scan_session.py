"""Claude DAST scan session — tracks AI scan history, cost, and session context."""
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class ClaudeScanSession(Base):
    __tablename__ = "claude_scan_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), nullable=False, unique=True, index=True)
    target_url = Column(Text, nullable=False)
    scan_mode = Column(String(20), default="standard")  # quick, standard, deep
    status = Column(String(20), default="running")  # running, completed, error, stopped, budget_exceeded

    # Models used during scan
    models_used = Column(JSONB, default=list)  # ["claude-sonnet-4-6", "claude-haiku-4-5"]
    primary_model = Column(String(64), nullable=True)

    # Token usage
    total_input_tokens = Column(Integer, default=0)
    total_output_tokens = Column(Integer, default=0)
    total_cached_tokens = Column(Integer, default=0)
    total_api_calls = Column(Integer, default=0)

    # Cost
    total_cost_usd = Column(Float, default=0.0)
    cost_breakdown = Column(JSONB, default=dict)  # {"haiku": 0.12, "sonnet": 1.45, ...}

    # Phase tracking
    phases_completed = Column(JSONB, default=list)  # ["crawling", "recon", "automated_checks", ...]
    current_phase = Column(String(30), nullable=True)

    # Results summary
    total_findings = Column(Integer, default=0)
    findings_by_severity = Column(JSONB, default=dict)  # {"critical": 1, "high": 2, ...}
    pages_crawled = Column(Integer, default=0)
    endpoints_tested = Column(Integer, default=0)
    new_test_cases = Column(Integer, default=0)
    pentest_options_offered = Column(Integer, default=0)

    # Session context (for continuity across scans)
    session_context_key = Column(String(128), nullable=True)  # Redis key for session context
    session_messages_count = Column(Integer, default=0)

    # Error info
    error = Column(Text, nullable=True)
    activity_log = Column(JSONB, default=list)  # Last 50 activity entries

    # Duration
    duration_seconds = Column(Integer, default=0)

    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
