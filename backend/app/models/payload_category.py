"""Payload category (PayloadsAllTheThings) and SecLists - stored in PostgreSQL."""
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, BigInteger
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.core.database import Base


class PayloadCategory(Base):
    __tablename__ = "payload_categories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug = Column(String(100), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    order_index = Column(Integer, nullable=True)
    has_readme = Column(Boolean, nullable=True)


class PayloadContent(Base):
    __tablename__ = "payload_contents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    category_id = Column(UUID(as_uuid=True), ForeignKey("payload_categories.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255), nullable=False)
    content = Column(String, nullable=True)


class SecListCategory(Base):
    __tablename__ = "seclist_categories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug = Column(String(100), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    order_index = Column(Integer, nullable=True)


class SecListFile(Base):
    __tablename__ = "seclist_files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    category_id = Column(UUID(as_uuid=True), ForeignKey("seclist_categories.id", ondelete="CASCADE"), nullable=False)
    path = Column(String(500), nullable=False)
    filename = Column(String(255), nullable=False)
    content = Column(String, nullable=True)
    size_bytes = Column(BigInteger, nullable=True)
