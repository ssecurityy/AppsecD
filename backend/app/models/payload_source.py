"""Payload source and wordlist files - FuzzDB, BLNS, XSS, SQLi, NoSQL, etc."""
from sqlalchemy import Column, String, Integer, Text, ForeignKey, DateTime, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.core.database import Base


class PayloadSource(Base):
    __tablename__ = "payload_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug = Column(String(100), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    repo_url = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    order_index = Column(Integer, nullable=True)
    synced_at = Column(DateTime, nullable=True)


class WordlistSourceFile(Base):
    __tablename__ = "wordlist_source_files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("payload_sources.id", ondelete="CASCADE"), nullable=False)
    category_path = Column(String(500), nullable=False)
    path = Column(String(500), nullable=False)
    filename = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    size_bytes = Column(BigInteger, nullable=True)
