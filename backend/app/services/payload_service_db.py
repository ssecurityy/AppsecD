"""Payload and SecLists service - 100% PostgreSQL, no filesystem dependency."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.payload_category import PayloadCategory, PayloadContent, SecListCategory, SecListFile
from app.models.payload_source import PayloadSource, WordlistSourceFile


async def get_payload_categories_db(db: AsyncSession) -> list[dict]:
    """List PayloadsAllTheThings categories from DB."""
    r = await db.execute(
        select(PayloadCategory).order_by(PayloadCategory.order_index, PayloadCategory.name)
    )
    cats = r.scalars().all()
    return [
        {"id": str(c.id), "name": c.name, "path": c.slug, "has_readme": c.has_readme or False, "order": i}
        for i, c in enumerate(cats)
    ]


def _to_slug(s: str) -> str:
    return s.replace(" ", "-").replace("_", "-").lower()


async def get_payload_content_db(db: AsyncSession, category: str, filename: str = "README.md") -> str | None:
    """Get payload content from DB. category can be UUID, slug, or display name."""
    import uuid
    try:
        uid = uuid.UUID(category)
        cat_r = await db.execute(select(PayloadCategory).where(PayloadCategory.id == uid))
        cat = cat_r.scalar_one_or_none()
    except ValueError:
        cat = None
    if cat is None:
        slug = _to_slug(category)
        cat_r = await db.execute(select(PayloadCategory).where(PayloadCategory.slug == slug))
        cat = cat_r.scalar_one_or_none()
    if cat is None:
        cat_r2 = await db.execute(select(PayloadCategory).where(PayloadCategory.name == category))
        cat = cat_r2.scalar_one_or_none()
    if not cat:
        return None
    r = await db.execute(
        select(PayloadContent).where(
            PayloadContent.category_id == cat.id,
            PayloadContent.filename == filename
        )
    )
    pc = r.scalar_one_or_none()
    if pc and pc.content:
        return pc.content
    # Fallback: first .md file
    r2 = await db.execute(select(PayloadContent).where(PayloadContent.category_id == cat.id))
    for row in r2.scalars().all():
        if row.filename.endswith(".md") and row.content:
            return row.content
    return None


async def get_seclists_categories_db(db: AsyncSession) -> list[dict]:
    """List SecLists categories from DB."""
    r = await db.execute(
        select(SecListCategory).order_by(SecListCategory.order_index, SecListCategory.name)
    )
    cats = r.scalars().all()
    return [
        {"id": str(c.id), "name": c.name, "path": c.slug, "order": i}
        for i, c in enumerate(cats)
    ]


async def list_wordlist_files_db(db: AsyncSession, category: str) -> list[dict]:
    """List wordlist files in a SecLists category from DB. category can be UUID or slug."""
    import uuid
    cat = None
    try:
        uid = uuid.UUID(category)
        cat_r = await db.execute(select(SecListCategory).where(SecListCategory.id == uid))
        cat = cat_r.scalar_one_or_none()
    except ValueError:
        pass
    if cat is None:
        cat_r = await db.execute(select(SecListCategory).where(SecListCategory.slug == _to_slug(category)))
        cat = cat_r.scalar_one_or_none()
    if cat is None:
        cat_r2 = await db.execute(select(SecListCategory).where(SecListCategory.name == category))
        cat = cat_r2.scalar_one_or_none()
    if not cat:
        return []
    r = await db.execute(
        select(SecListFile).where(SecListFile.category_id == cat.id).order_by(SecListFile.path)
    )
    files = r.scalars().all()
    return [
        {"path": f.path, "size": f.size_bytes or 0, "id": str(f.id), "filename": f.filename}
        for f in files
    ]


async def get_wordlist_content_db(db: AsyncSession, file_id: str) -> tuple[str, str] | None:
    """Get full wordlist content by file ID. Checks SecListFile then WordlistSourceFile."""
    import uuid
    try:
        uid = uuid.UUID(file_id)
    except ValueError:
        return None
    r = await db.execute(select(SecListFile).where(SecListFile.id == uid))
    f = r.scalar_one_or_none()
    if f and f.content:
        return (f.filename, f.content)
    r2 = await db.execute(select(WordlistSourceFile).where(WordlistSourceFile.id == uid))
    f2 = r2.scalar_one_or_none()
    if f2 and f2.content:
        return (f2.filename, f2.content)
    return None


async def get_payload_sources_db(db: AsyncSession) -> list[dict]:
    """List extra payload sources (FuzzDB, BLNS, XSS, SQLi, NoSQL, etc.)."""
    r = await db.execute(select(PayloadSource).order_by(PayloadSource.name))
    srcs = r.scalars().all()
    return [{"id": str(s.id), "slug": s.slug, "name": s.name, "repo_url": s.repo_url} for s in srcs]


async def list_source_files_db(db: AsyncSession, source_slug: str) -> list[dict]:
    """List files in a payload source."""
    r = await db.execute(select(PayloadSource).where(PayloadSource.slug == source_slug))
    src = r.scalar_one_or_none()
    if not src:
        return []
    r2 = await db.execute(
        select(WordlistSourceFile).where(WordlistSourceFile.source_id == src.id).order_by(WordlistSourceFile.path)
    )
    files = r2.scalars().all()
    return [
        {"path": f.path, "size": f.size_bytes or 0, "id": str(f.id), "filename": f.filename, "category_path": f.category_path}
        for f in files
    ]


async def get_wordlist_by_path_db(db: AsyncSession, category: str, subpath: str) -> tuple[str, str] | None:
    """Get wordlist content by category slug and relative path. Returns (filename, content) or None."""
    cat_r = await db.execute(select(SecListCategory).where(SecListCategory.slug == category))
    cat = cat_r.scalar_one_or_none()
    if not cat:
        return None
    path_clean = subpath.replace("\\", "/").lstrip("/")
    r = await db.execute(
        select(SecListFile).where(
            SecListFile.category_id == cat.id,
            SecListFile.path == path_clean
        )
    )
    f = r.scalar_one_or_none()
    if not f or not f.content:
        return None
    return (f.filename, f.content)
