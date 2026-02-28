"""Payload and wordlist source models (non-DB, in-memory)."""
from pydantic import BaseModel
from typing import List, Optional


class PayloadSource(BaseModel):
    name: str
    path: str
    description: Optional[str] = None
    files: List[str] = []


class WordlistSourceFile(BaseModel):
    name: str
    path: str
    description: Optional[str] = None
    size: Optional[int] = None
