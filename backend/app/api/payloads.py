"""Payload and wordlist API endpoints."""
from fastapi import APIRouter, HTTPException
from app.services import (
    get_payload_categories,
    get_payload_content,
    get_seclists_categories,
    list_wordlist_files,
    read_wordlist_preview,
)

router = APIRouter(prefix="/payloads", tags=["payloads"])


@router.get("/categories")
async def list_payload_categories():
    """List PayloadsAllTheThings categories."""
    return {"categories": get_payload_categories()}


@router.get("/categories/{category}/content")
async def get_category_content(category: str, file: str = "README.md"):
    """Get README or file content from a payload category."""
    content = get_payload_content(category, file)
    if content is None:
        raise HTTPException(404, f"Category or file not found: {category}/{file}")
    return {"category": category, "content": content}


@router.get("/seclists/categories")
async def list_seclists_categories():
    """List SecLists categories."""
    return {"categories": get_seclists_categories()}


@router.get("/seclists/categories/{category}/files")
async def list_category_wordlists(category: str):
    """List wordlist files in a SecLists category."""
    return {"files": list_wordlist_files(category)}


@router.get("/seclists/preview")
async def preview_wordlist(path: str, lines: int = 50):
    """Preview first N lines of a wordlist (path relative to SecLists root)."""
    from pathlib import Path
    from app.core.config import get_settings
    settings = get_settings()
    full_path = Path(settings.seclists_path) / path
    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(404, "File not found")
    preview = read_wordlist_preview(str(full_path), min(lines, 200))
    if preview is None:
        raise HTTPException(500, "Could not read file")
    return {"path": path, "lines": preview}
