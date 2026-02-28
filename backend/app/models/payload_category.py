"""Payload and SecList category models (non-DB, in-memory)."""
from pydantic import BaseModel
from typing import List, Optional


class PayloadContent(BaseModel):
    name: str
    path: str
    content: Optional[str] = None


class PayloadCategory(BaseModel):
    name: str
    path: str
    items: List[PayloadContent] = []


class SecListFile(BaseModel):
    name: str
    path: str
    content: Optional[str] = None


class SecListCategory(BaseModel):
    name: str
    path: str
    items: List[SecListFile] = []
