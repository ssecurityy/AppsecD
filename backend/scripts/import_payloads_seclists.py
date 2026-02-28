#!/usr/bin/env python3
"""Import PayloadsAllTheThings and SecLists from filesystem into PostgreSQL.
Run once when data folders exist. After import, app uses 100% DB - no filesystem dependency.
Usage: cd backend && python scripts/import_payloads_seclists.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.core.config import get_settings
from app.models.payload_category import PayloadCategory, PayloadContent, SecListCategory, SecListFile

MAX_WORDLIST_SIZE = 200 * 1024 * 1024  # 200MB - load 100%, no skip


def _slug(name: str) -> str:
    return name.replace(" ", "-").replace("_", "-").lower()


def import_payloads_all_the_things(base: Path) -> list[tuple[PayloadCategory, list[PayloadContent]]]:
    """Import PAT categories and their README/content files."""
    items = []
    for i, p in enumerate(sorted(base.iterdir())):
        if not p.is_dir() or p.name.startswith(".") or p.name == "_template_vuln":
            continue
        slug = _slug(p.name)
        readme = p / "README.md"
        has_readme = readme.exists()
        cat = PayloadCategory(slug=slug, name=p.name.replace("-", " ").replace("_", " ").title(), order_index=i, has_readme=has_readme)
        contents = []
        for f in p.iterdir():
            if f.is_file() and f.suffix.lower() in (".md", ".txt"):
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    contents.append(PayloadContent(filename=f.name, content=text))
                except Exception as e:
                    print(f"  Skip {f}: {e}")
        if not contents and has_readme:
            try:
                contents.append(PayloadContent(filename="README.md", content=readme.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                pass
        if not contents:
            for fallback in ("INDEX.md", "BOOKS.md"):
                fp = p / fallback
                if fp.exists():
                    try:
                        contents.append(PayloadContent(filename=fallback, content=fp.read_text(encoding="utf-8", errors="replace")))
                        break
                    except Exception:
                        pass
        items.append((cat, contents))
    return items


def iter_seclist_categories(base: Path):
    """Yield (category, file_iter) to avoid loading all content in memory."""
    for i, p in enumerate(sorted(base.iterdir())):
        if not p.is_dir() or p.name.startswith(".") or p.name in (".git", ".bin"):
            continue
        slug = _slug(p.name)
        cat = SecListCategory(slug=slug, name=p.name.replace("-", " ").replace("_", " ").title(), order_index=i)

        def file_iter(cat_path=p):
            for fp in cat_path.rglob("*"):
                if fp.is_file() and fp.suffix.lower() in (".txt", ".csv", ".json", "") and fp.suffix != ".md":
                    rel = fp.relative_to(cat_path)
                    path_str = str(rel).replace("\\", "/")
                    size = fp.stat().st_size
                    if size > MAX_WORDLIST_SIZE:
                        print(f"  Skip (>{MAX_WORDLIST_SIZE//1024**2}MB): {path_str}")
                        continue
                    try:
                        content = fp.read_text(encoding="utf-8", errors="replace")
                        content = content.replace("\x00", "")  # PostgreSQL rejects null bytes
                        yield (path_str, fp.name, size, content)
                    except Exception as e:
                        print(f"  Skip {path_str}: {e}")

        yield cat, file_iter


async def run():
    settings = get_settings()
    pat_base = Path(settings.payloads_path)
    sl_base = Path(settings.seclists_path)

    if not pat_base.exists():
        print(f"PayloadsAllTheThings not found at {pat_base}. Skipping PAT import.")
        pat_data = []
    else:
        print("Importing PayloadsAllTheThings...")
        pat_data = import_payloads_all_the_things(pat_base)
        print(f"  Found {len(pat_data)} categories")

    sl_categories = list(iter_seclist_categories(sl_base)) if sl_base.exists() else []
    if not sl_base.exists():
        print(f"SecLists not found at {sl_base}. Skipping SecLists import.")
    else:
        print(f"Importing SecLists ({len(sl_categories)} categories)...")

    async with AsyncSessionLocal() as db:
        # Clear existing (order: children first due to FK)
        from sqlalchemy import text
        await db.execute(text("DELETE FROM seclist_files"))
        await db.execute(text("DELETE FROM seclist_categories"))
        await db.execute(text("DELETE FROM payload_contents"))
        await db.execute(text("DELETE FROM payload_categories"))
        await db.commit()

        # Import PAT
        for cat, contents in pat_data:
            db.add(cat)
            await db.flush()
            for c in contents:
                c.category_id = cat.id
                db.add(c)
        await db.commit()
        print(f"Imported {len(pat_data)} PAT categories")

        # Import SecLists - stream category by category to avoid OOM
        total_files = 0
        for cat, file_iter in sl_categories:
            db.add(cat)
            await db.flush()
            for path_str, filename, size, content in file_iter():
                sf = SecListFile(category_id=cat.id, path=path_str, filename=filename, content=content, size_bytes=size)
                db.add(sf)
                total_files += 1
            await db.commit()
            if total_files % 500 == 0 or total_files < 500:
                print(f"  Committed {total_files} files...")
        print(f"Imported {len(sl_categories)} SecLists categories, {total_files} files")

    print("Done. App now uses 100% PostgreSQL for payloads and wordlists.")


if __name__ == "__main__":
    asyncio.run(run())
