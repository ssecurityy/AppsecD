"""Organization model for multi-tenant support."""
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, Float, Numeric
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    logo_url = Column(Text, nullable=True)
    brand_color = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Claude AI DAST — enterprise controls
    claude_enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    claude_monthly_budget_usd = Column(Numeric(10, 2), nullable=True)  # null = unlimited
    claude_per_scan_limit_usd = Column(Numeric(10, 2), nullable=True, server_default="20.00")
    claude_allowed_models = Column(JSONB, nullable=True, server_default='["claude-haiku-4-5","claude-sonnet-4-6","claude-opus-4-6"]')
    claude_max_scans_per_day = Column(Integer, nullable=True, server_default="50")
    claude_deep_scan_approval_required = Column(Boolean, default=True, nullable=False, server_default="true")
    claude_dast_api_key = Column(Text, nullable=True)  # Per-org Anthropic API key override

    # SLA policy: days allowed per severity (e.g. {"critical": 1, "high": 3, "medium": 7, "low": 30, "info": 90})
    sla_policy = Column(JSONB, nullable=True, server_default='{"critical": 1, "high": 3, "medium": 7, "low": 30, "info": 90}')

    # SAST — enterprise controls
    sast_enabled = Column(Boolean, default=False, nullable=False, server_default="false")
    sast_monthly_budget_usd = Column(Numeric(10, 2), nullable=True)  # null = unlimited
    sast_max_scans_per_day = Column(Integer, nullable=True, server_default="20")
    sast_ai_analysis_enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    sast_github_app_installation_id = Column(String(100), nullable=True)

    # Code Security Platform — extended controls (028 migration)
    sast_claude_review_enabled = Column(Boolean, default=False, nullable=False, server_default="false")
    sast_pr_review_enabled = Column(Boolean, default=False, nullable=False, server_default="false")
    sast_pr_review_block_on_high = Column(Boolean, default=True, nullable=False, server_default="true")
    sast_sca_enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    sast_blocked_licenses = Column(JSONB, nullable=True)
    sast_iac_scanning_enabled = Column(Boolean, default=True, nullable=False, server_default="true")

    # Production hardening — extended controls (029 migration)
    sast_custom_exclusion_patterns = Column(JSONB, nullable=True)
    sast_confidence_threshold = Column(Float, server_default="0.7", nullable=True)
    sast_sla_policy = Column(JSONB, nullable=True,
                             server_default='{"critical": 1, "high": 3, "medium": 7, "low": 30, "info": 90}')
    sast_custom_instructions = Column(Text, nullable=True)
