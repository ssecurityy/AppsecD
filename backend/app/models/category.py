"""Category / Phase model."""
from sqlalchemy import Column, String, Integer, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.core.database import Base


class Category(Base):
    __tablename__ = "categories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    phase = Column(String(50), nullable=False)
    icon = Column(String(50))
    description = Column(Text)
    order_index = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
