"""Code source extraction — ZIP upload, Git clone, language detection."""
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

# Max ZIP size: 500MB
MAX_ZIP_SIZE = 500 * 1024 * 1024
# Max extraction ratio (zip bomb protection)
MAX_EXTRACTION_RATIO = 100
# Max files to scan
MAX_FILES = 50_000

# Directories to skip
EXCLUDE_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", "dist", "build",
    ".next", ".nuxt", "venv", ".venv", "env", ".env", ".tox",
    "target", "bin", "obj", ".idea", ".vscode", ".svn", ".hg",
    "bower_components", "jspm_packages", ".cache", ".parcel-cache",
    "coverage", ".nyc_output", "eggs",
}

# Language detection by extension (aligned with Semgrep registry + common ecosystems)
LANGUAGE_EXTENSIONS = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala", ".sc": "scala",
    ".r": "r", ".R": "r",
    ".sh": "bash", ".bash": "bash",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".sql": "sql",
    ".tf": "terraform", ".hcl": "terraform",
    ".dockerfile": "dockerfile",
    ".ex": "elixir", ".exs": "elixir",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    # Extended coverage (2026+)
    ".sol": "solidity",
    ".groovy": "groovy", ".gradle": "groovy",
    ".dart": "dart",
    ".vb": "vb", ".vbs": "vb",
    ".vue": "javascript",
    ".svelte": "javascript",
    ".cls": "apex", ".trigger": "apex",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
    ".ml": "ocaml", ".mli": "ocaml",
}


def extract_zip(zip_path: str, extract_dir: str | None = None) -> str:
    """Extract a ZIP file safely with zip bomb protection.

    Returns path to extracted directory.
    """
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    file_size = os.path.getsize(zip_path)
    if file_size > MAX_ZIP_SIZE:
        raise ValueError(f"ZIP file too large: {file_size / 1024 / 1024:.1f}MB (max {MAX_ZIP_SIZE / 1024 / 1024}MB)")

    if extract_dir is None:
        extract_dir = tempfile.mkdtemp(prefix="sast_scan_")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Check total uncompressed size (zip bomb protection)
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if file_size > 0 and total_uncompressed / file_size > MAX_EXTRACTION_RATIO:
                raise ValueError(
                    f"Zip bomb detected: compression ratio {total_uncompressed / file_size:.0f}x "
                    f"exceeds max {MAX_EXTRACTION_RATIO}x"
                )

            # Check file count
            if len(zf.infolist()) > MAX_FILES:
                raise ValueError(f"Too many files in ZIP: {len(zf.infolist())} (max {MAX_FILES})")

            # Extract safely — prevent path traversal
            for info in zf.infolist():
                # Reject absolute paths and path traversal
                if info.filename.startswith("/") or ".." in info.filename:
                    logger.warning("Skipping unsafe path: %s", info.filename)
                    continue
                # Use realpath to verify extraction stays within target directory
                target_path = os.path.realpath(os.path.join(extract_dir, info.filename))
                real_extract_dir = os.path.realpath(extract_dir)
                if not target_path.startswith(real_extract_dir + os.sep) and target_path != real_extract_dir:
                    logger.warning("Path traversal blocked: %s resolves outside target dir", info.filename)
                    continue
                zf.extract(info, extract_dir)

    except zipfile.BadZipFile:
        raise ValueError("Invalid ZIP file")

    return extract_dir


def clone_repo(repo_url: str, branch: str = "main", token: str | None = None,
               clone_dir: str | None = None) -> str:
    """Shallow clone a git repository.

    Returns path to cloned directory.
    """
    if clone_dir is None:
        clone_dir = tempfile.mkdtemp(prefix="sast_repo_")

    # Build auth URL if token provided
    if token:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(repo_url)
        auth_url = urlunparse(parsed._replace(netloc=f"x-access-token:{token}@{parsed.hostname}"))
    else:
        auth_url = repo_url

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, "--single-branch", auth_url, clone_dir],
            capture_output=True, text=True, timeout=120,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Git clone failed: {e.stderr[:500]}")
    except subprocess.TimeoutExpired:
        raise ValueError("Git clone timed out (120s)")

    return clone_dir


def detect_languages(source_dir: str) -> dict:
    """Detect languages in a source directory by counting lines per language.

    Returns: {language: line_count, ...}
    """
    lang_lines: Counter = Counter()
    file_count = 0

    for root, dirs, files in os.walk(source_dir):
        # Skip excluded directories (including *.egg-info pattern)
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")]

        for fname in files:
            if file_count >= MAX_FILES:
                break
            ext = os.path.splitext(fname)[1].lower()
            lang = LANGUAGE_EXTENSIONS.get(ext)
            if lang:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as fh:
                        line_count = sum(1 for _ in fh)
                    lang_lines[lang] += line_count
                    file_count += 1
                except (OSError, UnicodeDecodeError):
                    continue

    return dict(lang_lines.most_common())


def list_scannable_files(source_dir: str) -> list[str]:
    """List all source files eligible for scanning.

    Returns list of relative paths.
    """
    files = []
    for root, dirs, filenames in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in LANGUAGE_EXTENSIONS:
                rel = os.path.relpath(os.path.join(root, fname), source_dir)
                files.append(rel)
                if len(files) >= MAX_FILES:
                    return files
    return files


def cleanup_source(source_dir: str) -> None:
    """Remove extracted/cloned source directory."""
    try:
        if os.path.isdir(source_dir):
            shutil.rmtree(source_dir, ignore_errors=True)
    except Exception as e:
        logger.warning("Failed to cleanup %s: %s", source_dir, e)


def compute_file_hash(file_path: str) -> str:
    """Compute SHA256 hash of a file for dedup."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:32]


# ── Diff-aware scanning support ──────────────────────────────────────

def get_changed_files(repo_path: str, base_branch: str, head_branch: str = "HEAD") -> list[str]:
    """Get list of changed files between two branches/refs.

    Returns list of relative file paths.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_branch}...{head_branch}"],
            capture_output=True, text=True, timeout=60, cwd=repo_path,
        )
        if result.returncode != 0:
            logger.warning("git diff failed: %s", result.stderr[:200])
            return []
        return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.warning("get_changed_files failed: %s", e)
        return []


def get_file_diff(repo_path: str, file_path: str, base_branch: str) -> str:
    """Get unified diff for a single file."""
    try:
        result = subprocess.run(
            ["git", "diff", f"{base_branch}...HEAD", "--", file_path],
            capture_output=True, text=True, timeout=30, cwd=repo_path,
        )
        return result.stdout if result.returncode == 0 else ""
    except (subprocess.TimeoutExpired, Exception):
        return ""


def detect_iac_files(source_dir: str) -> dict:
    """Detect IaC file types in a source directory.

    Returns: {"terraform": count, "kubernetes": count, "dockerfile": count, ...}
    """
    iac_counts: Counter = Counter()
    iac_indicators = {
        ".tf": "terraform",
        ".tfvars": "terraform",
        "Dockerfile": "dockerfile",
        ".yaml": None,
        ".yml": None,
    }

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            basename = os.path.basename(fname)

            if basename == "Dockerfile" or basename.startswith("Dockerfile."):
                iac_counts["dockerfile"] += 1
            elif basename in ("docker-compose.yml", "docker-compose.yaml",
                            "compose.yml", "compose.yaml"):
                iac_counts["docker_compose"] += 1
            elif ext in (".tf", ".tfvars"):
                iac_counts["terraform"] += 1
            elif ext in (".yaml", ".yml"):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as fh:
                        head = fh.read(2000)
                    if "AWSTemplateFormatVersion" in head:
                        iac_counts["cloudformation"] += 1
                    elif "kind:" in head and any(
                        k in head for k in ("Deployment", "Pod", "Service",
                                            "StatefulSet", "DaemonSet")
                    ):
                        iac_counts["kubernetes"] += 1
                    if basename in ("values.yaml", "values.yml"):
                        chart = os.path.join(os.path.dirname(fpath), "Chart.yaml")
                        if os.path.isfile(chart):
                            iac_counts["helm"] += 1
                except (OSError, UnicodeDecodeError):
                    pass

    return dict(iac_counts)
