"""Claude AI crawl result — stores AI-driven crawl data with full request/response."""
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from app.core.database import Base


class ClaudeCrawlResult(Base):
    __tablename__ = "claude_crawl_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), nullable=False, index=True)

    # Every crawled page with full detail
    # [{url, method, status_code, content_type, size,
    #   request_raw, response_headers, response_body_preview,
    #   forms[], links[], scripts[], cookies[],
    #   technology_detected[], interesting_findings[]}]
    crawled_pages = Column(JSONB, default=list)

    # Discovered assets
    api_endpoints = Column(JSONB, default=list)  # [{url, method, params, auth_required, schema}]
    js_files = Column(JSONB, default=list)  # [{url, size, secrets[], libraries[], endpoints_found[]}]
    subdomains = Column(JSONB, default=list)  # [{subdomain, ip, status, technologies[]}]
    hidden_paths = Column(JSONB, default=list)  # [{path, status, how_found, wordlist_used}]
    hidden_parameters = Column(JSONB, default=list)  # [{url, param, type, how_found}]
    forms_discovered = Column(JSONB, default=list)  # [{url, action, method, fields[]}]

    # Analysis
    technology_stack = Column(JSONB, default=dict)  # {server, framework, language, db, cdn, waf}
    attack_surface_summary = Column(Text, nullable=True)

    # SCA (Software Composition Analysis) from JS
    sca_results = Column(JSONB, default=list)  # [{library, version, cves[], risk}]

    # Secrets found in client-side code
    secrets_found = Column(JSONB, default=list)  # [{type, value_preview, file, line}]

    # Stats
    total_pages = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    total_parameters = Column(Integer, default=0)
    total_forms = Column(Integer, default=0)
    total_js_files = Column(Integer, default=0)
    total_subdomains = Column(Integer, default=0)
    duration_seconds = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
