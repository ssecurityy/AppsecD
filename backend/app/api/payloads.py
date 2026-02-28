"""Payload and wordlist API - 100% PostgreSQL, no filesystem dependency."""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.payload_service_db import (
    get_payload_categories_db,
    get_payload_content_db,
    get_seclists_categories_db,
    list_wordlist_files_db,
    get_wordlist_content_db,
    get_wordlist_by_path_db,
    get_payload_sources_db,
    list_source_files_db,
)

router = APIRouter(prefix="/payloads", tags=["payloads"])


@router.get("/categories")
async def list_payload_categories(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List PayloadsAllTheThings categories from DB."""
    cats = await get_payload_categories_db(db)
    return {"categories": cats}


@router.get("/categories/{category}/content")
async def get_category_content(
    category: str,
    file: str = "README.md",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get README or file content from a payload category."""
    content = await get_payload_content_db(db, category, file)
    if content is None:
        raise HTTPException(404, f"Category or file not found: {category}/{file}")
    return {"category": category, "content": content}


@router.get("/seclists/categories")
async def list_seclists_categories(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List SecLists categories from DB."""
    cats = await get_seclists_categories_db(db)
    return {"categories": cats}


@router.get("/seclists/categories/{category}/files")
async def list_category_wordlists(
    category: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List wordlist files in a SecLists category."""
    files = await list_wordlist_files_db(db, category)
    return {"files": files}


@router.get("/seclists/preview")
async def preview_wordlist(
    path: str = None,
    file_id: str = None,
    lines: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Preview first N lines. Use file_id=uuid or path=category/subpath (e.g. Discovery/Web-Content/file.txt)."""
    if file_id:
        result = await get_wordlist_content_db(db, file_id)
    elif path:
        parts = path.replace("\\", "/").strip("/").split("/", 1)
        cat = parts[0]
        subpath = parts[1] if len(parts) > 1 else ""
        result = await get_wordlist_by_path_db(db, cat, subpath)
    else:
        raise HTTPException(400, "Provide file_id or path")
    if not result:
        raise HTTPException(404, "File not found")
    filename, content = result
    line_list = content.splitlines()[:min(lines, 200)]
    return {"path": path or file_id, "lines": line_list, "filename": filename}


@router.get("/seclists/download/{file_id}", response_class=PlainTextResponse)
async def download_wordlist(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Download full wordlist file as plain text (for copy or save)."""
    result = await get_wordlist_content_db(db, file_id)
    if not result:
        raise HTTPException(404, "File not found")
    filename, content = result
    return PlainTextResponse(
        content=content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/seclists/content/{file_id}")
async def get_wordlist_content(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full wordlist content as JSON (for copy to clipboard). Works for SecLists + FuzzDB/BLNS/XSS/SQLi/NoSQL."""
    result = await get_wordlist_content_db(db, file_id)
    if not result:
        raise HTTPException(404, "File not found")
    filename, content = result
    return {"filename": filename, "content": content, "lines": content.splitlines()}


@router.get("/sources")
async def list_payload_sources(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List extra payload sources: FuzzDB, BLNS, XSS, SQLi, NoSQL, Nuclei, Intruder."""
    return {"sources": await get_payload_sources_db(db)}


@router.get("/sources/{source_slug}/files")
async def list_source_wordlists(
    source_slug: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List wordlist files in a payload source."""
    return {"files": await list_source_files_db(db, source_slug)}
