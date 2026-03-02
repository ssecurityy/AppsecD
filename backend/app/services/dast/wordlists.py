"""DAST wordlists: paths and loading. IntruderPayloads + SecLists fallbacks."""
import logging
from pathlib import Path

from .base import DATA_ROOT

logger = logging.getLogger(__name__)

# IntruderPayloads first (always present); SecLists for fuller coverage
WORDLIST_PATHS = [
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-quick.txt",
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-top1000.txt",
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-dirs.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-small.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-lowercase-2.3-small.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Common-DB-Backups.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Logins.fuzz.txt",
]

# Full wordlists: IntruderPayloads first for reliability when SecLists absent
FULL_WORDLIST_PATHS = [
    ("dirbuster-quick", DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-quick.txt"),
    ("dirbuster-top1000", DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-top1000.txt"),
    ("dirbuster-dirs", DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-dirs.txt"),
    ("small", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-small.txt"),
    ("medium", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-medium.txt"),
    ("api-common", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Logins.fuzz.txt"),
]

DEFAULT_WORDLIST_FALLBACK = [
    "admin", "login", "api", "config", "backup", "static", "assets", "uploads",
    "images", "css", "js", "wp-admin", ".git", ".env", "debug", "test", "dev",
    "staging", "dashboard", "panel",
]


def load_discovery_wordlist(max_paths: int = 400) -> list[str]:
    """Load and merge from multiple wordlists. Prefers IntruderPayloads then SecLists."""
    seen = set()
    merged: list[str] = []
    for p in WORDLIST_PATHS:
        if not p.exists():
            continue
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    w = ln.strip()
                    if not w or w.startswith("#"):
                        continue
                    w = w.lstrip("/")
                    if w and w not in seen:
                        seen.add(w)
                        merged.append(w)
                        if len(merged) >= max_paths:
                            return merged
        except Exception as e:
            logger.debug("Could not load wordlist %s: %s", p, e)
    if not merged:
        return DEFAULT_WORDLIST_FALLBACK.copy()
    return merged


def get_available_full_wordlists() -> list[tuple[str, Path]]:
    """Return only wordlists that exist. Used by exhaustive scan."""
    return [(k, p) for k, p in FULL_WORDLIST_PATHS if p.exists()]


def get_wordlist_path(wordlist_key: str) -> tuple[str, Path] | None:
    """Resolve wordlist by key. Falls back to first available if key not found."""
    for key, p in FULL_WORDLIST_PATHS:
        if key == wordlist_key and p.exists():
            return (key, p)
    for key, p in FULL_WORDLIST_PATHS:
        if p.exists():
            return (key, p)
    return None
