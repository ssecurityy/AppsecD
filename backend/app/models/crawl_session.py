"""Crawl session model — stores spider/crawler results per project."""
from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from datetime import datetime
import uuid
from app.core.database import Base


class CrawlSession(Base):
    __tablename__ = "crawl_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    crawl_id = Column(String(64), nullable=False, index=True)
    target_url = Column(Text, nullable=False)
    status = Column(String(20), default="running")  # running, completed, error
    crawl_type = Column(String(20), default="full")  # full, authenticated, directory
    auth_type = Column(String(20), nullable=True)  # header, cookie, custom_headers, credentials, none

    # Results
    urls = Column(JSONB, default=list)  # All discovered URLs [{url, method, status_code, source}]
    api_endpoints = Column(JSONB, default=list)  # API endpoints [{url, method, parameters, body_params}]
    parameters = Column(JSONB, default=list)  # Discovered params [{name, values, source, url}]
    forms = Column(JSONB, default=list)  # Forms [{url, method, parameters}]
    js_files = Column(JSONB, default=list)  # JS files [{url, status_code, source}]
    pages = Column(JSONB, default=list)  # HTML pages [{url, method, status_code}]

    # Stats
    total_urls = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    total_parameters = Column(Integer, default=0)
    total_forms = Column(Integer, default=0)
    total_js_files = Column(Integer, default=0)
    duration_seconds = Column(Integer, default=0)
    max_depth = Column(Integer, default=3)
    crawl_scope = Column(String(20), default="host")

    # Directory scan results (if crawl_type=directory)
    directory_tree = Column(JSONB, default=list)  # Nested tree [{path, status, type, children: [...]}]
    directory_flat = Column(JSONB, default=list)  # Flat list [{path, status, type, depth}]

    # JS/crawl enhancements
    deeplinks = Column(JSONB, default=list)  # Discovered deeplinks (app://, intent://)
    js_sca = Column(JSONB, nullable=True)  # {libraries, vulnerabilities, summary}
    retire_results = Column(JSONB, nullable=True)  # Retire.js output
    crawler_used = Column(String(32), nullable=True)  # katana | spider_rs | httpx

    error = Column(Text, nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
