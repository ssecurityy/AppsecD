"""DAST wordlists: paths and loading. IntruderPayloads + SecLists; R2 or local."""
import logging
import tempfile
from pathlib import Path

from app.core.storage import KEY_PREFIX_WORDLISTS
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

# Cache dir for R2-downloaded wordlists (so ffuf gets a real file path)
_wordlist_cache_dir: Path | None = None


def _wordlist_cache_dir_path() -> Path:
    global _wordlist_cache_dir
    if _wordlist_cache_dir is None:
        _wordlist_cache_dir = Path(tempfile.gettempdir()) / "navigator_wordlists"
        _wordlist_cache_dir.mkdir(parents=True, exist_ok=True)
    return _wordlist_cache_dir


def _path_to_r2_key(path: Path) -> str:
    """Build R2 key for a wordlist path under DATA_ROOT."""
    try:
        rel = path.relative_to(DATA_ROOT)
    except ValueError:
        return ""
    return f"{KEY_PREFIX_WORDLISTS}/{rel.as_posix()}"


def _get_wordlist_content(path: Path) -> bytes | None:
    """Get wordlist bytes from R2 (if storage is R2 and key exists) or local file. No throw."""
    try:
        from app.core.storage import get_storage
        storage = get_storage()
        if getattr(storage, "bucket", None):  # R2
            r2_key = _path_to_r2_key(path)
            if r2_key:
                data = storage.get(r2_key)
                if data:
                    return data
    except Exception as e:
        logger.debug("R2 wordlist get %s: %s", path, e)
    if path.exists():
        try:
            return path.read_bytes()
        except Exception as e:
            logger.debug("Local wordlist read %s: %s", path, e)
    return None


def _resolve_wordlist_path(key: str, path: Path) -> Path | None:
    """Resolve to a concrete file Path: from R2 (cached to temp) or local. Returns None if unavailable."""
    try:
        from app.core.storage import get_storage
        storage = get_storage()
        if getattr(storage, "bucket", None):
            r2_key = _path_to_r2_key(path)
            if r2_key:
                data = storage.get(r2_key)
                if data:
                    cache_dir = _wordlist_cache_dir_path()
                    safe_name = r2_key.replace("/", "_").replace("\\", "_")
                    cache_file = cache_dir / safe_name
                    cache_file.write_bytes(data)
                    return cache_file
    except Exception as e:
        logger.debug("R2 wordlist resolve %s: %s", path, e)
    if path.exists():
        return path
    return None


def load_discovery_wordlist(max_paths: int = 400) -> list[str]:
    """Load and merge from multiple wordlists. Prefers R2 then local (IntruderPayloads then SecLists)."""
    seen = set()
    merged: list[str] = []
    for p in WORDLIST_PATHS:
        content = _get_wordlist_content(p)
        if not content:
            continue
        try:
            for ln in content.decode("utf-8", errors="ignore").splitlines():
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
    """Return only wordlists that exist (in R2 or on local disk). Used by exhaustive scan."""
    out: list[tuple[str, Path]] = []
    for k, p in FULL_WORDLIST_PATHS:
        resolved = _resolve_wordlist_path(k, p)
        if resolved is not None:
            out.append((k, resolved))
    return out


def get_wordlist_path(wordlist_key: str) -> tuple[str, Path] | None:
    """Resolve wordlist by key (R2 or local). Falls back to first available if key not found."""
    for key, p in FULL_WORDLIST_PATHS:
        if key == wordlist_key:
            resolved = _resolve_wordlist_path(key, p)
            if resolved is not None:
                return (key, resolved)
    for key, p in FULL_WORDLIST_PATHS:
        resolved = _resolve_wordlist_path(key, p)
        if resolved is not None:
            return (key, resolved)
    return None
