"""Payload and wordlist service - reads from PayloadsAllTheThings and SecLists."""
import os
from pathlib import Path
from typing import Optional
from app.core.config import get_settings


def _safe_listdir(path: Path) -> list[str]:
    try:
        return [p.name for p in path.iterdir()] if path.exists() else []
    except Exception:
        return []


def get_payload_categories() -> list[dict]:
    """List categories from PayloadsAllTheThings."""
    settings = get_settings()
    base = Path(settings.payloads_path)
    if not base.exists():
        return []
    items = []
    for i, name in enumerate(sorted(_safe_listdir(base))):
        p = base / name
        if p.is_dir() and not name.startswith(".") and name != "_template_vuln":
            readme = p / "README.md"
            items.append({
                "id": name,
                "name": name.replace("-", " ").replace("_", " ").title(),
                "path": str(p),
                "has_readme": readme.exists(),
                "order": i,
            })
    return items


def get_payload_content(category: str, filename: str = "README.md") -> Optional[str]:
    """Read content from PayloadsAllTheThings."""
    settings = get_settings()
    base = Path(settings.payloads_path) / category
    path = base / filename
    if path.exists() and path.is_file():
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
    # Fallback for categories without README (e.g. _LEARNING_AND_SOCIALS)
    for fallback in ("INDEX.md", "BOOKS.md", "README.md"):
        p = base / fallback
        if p.exists() and p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
    # Try first .md file
    if base.exists():
        for f in sorted(base.iterdir()):
            if f.suffix == ".md":
                try:
                    return f.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
    return None


def get_seclists_categories() -> list[dict]:
    """List categories from SecLists."""
    settings = get_settings()
    base = Path(settings.seclists_path)
    if not base.exists():
        return []
    items = []
    for i, name in enumerate(sorted(_safe_listdir(base))):
        p = base / name
        if p.is_dir() and not name.startswith("."):
            items.append({
                "id": name,
                "name": name.replace("-", " ").replace("_", " ").title(),
                "path": str(p),
                "order": i,
            })
    return items


def get_wordlist_path(
    category: str,
    subpath: str,
) -> Optional[str]:
    """Get full path to a wordlist file in SecLists."""
    settings = get_settings()
    path = Path(settings.seclists_path) / category / subpath
    if path.exists() and path.is_file():
        return str(path)
    return None


def list_wordlist_files(category: str) -> list[dict]:
    """List wordlist files in a SecLists category."""
    settings = get_settings()
    base = Path(settings.seclists_path) / category
    if not base.exists() or not base.is_dir():
        return []
    items = []
    for p in base.rglob("*"):
        if p.is_file() and p.suffix in (".txt", ".csv", ".json", ""):
            rel = p.relative_to(base)
            items.append({
                "path": str(rel),
                "size": p.stat().st_size,
                "full_path": str(p),
            })
    return items[:500]


def read_wordlist_preview(path: str, lines: int = 50) -> Optional[list[str]]:
    """Read first N lines of a wordlist."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip() for line in f.readlines()[:lines]]
    except Exception:
        return None
