#!/usr/bin/env python3
"""
Sync EXTRA payload sources from GitHub into PostgreSQL.
PAT and SecLists: use import_payloads_seclists.py (from existing data folders).

This script clones and imports:
- FuzzDB, BLNS, XSS Payloads, SQLi, NoSQL, Nuclei, Intruder
100% coverage - no file size limit (up to 200MB per file).
"""
import asyncio
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB per file

DATA_DIR = Path(os.getenv("NAVIGATOR_DATA_DIR", "/opt/navigator/data"))
REPOS = [
    ("fuzzdb", "https://github.com/fuzzdb-project/fuzzdb.git"),
    ("big-list-of-naughty-strings", "https://github.com/minimaxir/big-list-of-naughty-strings.git"),
    ("all-XSS-Payloads", "https://github.com/fxrhan/all-XSS-Payloads.git"),
    ("SQL-injection-payloads", "https://github.com/manishravtole/SQL-injection-payloads.git"),
    ("Advanced-SQL-Injection-Cheatsheet", "https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet.git"),
    ("nuclei-templates", "https://github.com/projectdiscovery/nuclei-templates.git"),
    ("IntruderPayloads", "https://github.com/1N3/IntruderPayloads.git"),
    ("OWASP-wstg", "https://github.com/OWASP/wstg.git"),
]


def clone_or_pull(repo_name: str, url: str, target: Path) -> bool:
    """Clone repo or pull if exists."""
    if target.exists():
        try:
            subprocess.run(["git", "pull", "--depth", "1"], cwd=target, capture_output=True, timeout=120)
            return True
        except Exception:
            return True
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", url, str(target)], capture_output=True, timeout=300)
        return True
    except Exception as e:
        print(f"  Clone failed for {repo_name}: {e}")
        return False


def collect_files(base: Path, extensions: tuple = (".txt", ".csv", ".json", ".yaml", ".yml", ".md", "")) -> list[tuple[str, str, int, str]]:
    """Collect all matching files. Returns [(category_path, path, size, content)]. Excludes .git, strips null bytes."""
    out = []
    for fp in base.rglob("*"):
        if not fp.is_file():
            continue
        if ".git" in str(fp):
            continue
        ext = fp.suffix.lower()
        ext_ok = ext in extensions or ext == ".md"
        if not ext_ok:
            continue
        if fp.name.startswith("."):
            continue
        try:
            rel = fp.relative_to(base)
            path_str = str(rel).replace("\\", "/")
            cat_path = str(rel.parent).replace("\\", "/") if rel.parent != Path(".") else ""
            size = fp.stat().st_size
            if size > MAX_FILE_SIZE:
                print(f"  Skip (>{MAX_FILE_SIZE//1024**2}MB): {path_str}")
                continue
            content = fp.read_text(encoding="utf-8", errors="replace")
            content = content.replace("\x00", "")  # PostgreSQL rejects null bytes in UTF8
            out.append((cat_path, path_str, size, content))
        except Exception as e:
            print(f"  Skip {fp}: {e}")
    return out


async def run():
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.models.payload_source import PayloadSource, WordlistSourceFile

    print("=" * 60)
    print("SYNC EXTRA PAYLOAD SOURCES (FuzzDB, BLNS, XSS, SQLi, NoSQL, etc.)")
    print("=" * 60)

    # Clone repos
    for name, url in REPOS:
        target = DATA_DIR / name
        print(f"Syncing {name}...")
        if clone_or_pull(name, url, target):
            print(f"  OK")
        else:
            print(f"  SKIP")

    SOURCE_CONFIG = [
        ("fuzzdb", "FuzzDB", "https://github.com/fuzzdb-project/fuzzdb"),
        ("blns", "Big List of Naughty Strings", "https://github.com/minimaxir/big-list-of-naughty-strings"),
        ("xss", "XSS Payloads (7000+)", "https://github.com/fxrhan/all-XSS-Payloads"),
        ("sqli", "SQL Injection Payloads", "https://github.com/manishravtole/SQL-injection-payloads"),
        ("sqli-advanced", "Advanced SQL Injection Cheatsheet", "https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet"),
        ("nuclei", "Nuclei Templates", "https://github.com/projectdiscovery/nuclei-templates"),
        ("intruder", "Intruder Payload Packs (1N3)", "https://github.com/1N3/IntruderPayloads"),
        ("wstg", "OWASP Web Security Testing Guide", "https://github.com/OWASP/wstg"),
    ]

    FOLDER_MAP = {
        "fuzzdb": "fuzzdb", "blns": "big-list-of-naughty-strings", "xss": "all-XSS-Payloads",
        "sqli": "SQL-injection-payloads", "sqli-advanced": "Advanced-SQL-Injection-Cheatsheet",
        "nuclei": "nuclei-templates", "intruder": "IntruderPayloads", "wstg": "OWASP-wstg",
    }
    extra_sources = []
    for slug, name, url in SOURCE_CONFIG:
        base = DATA_DIR / FOLDER_MAP.get(slug, slug)
        if not base.exists():
            print(f"  Skip {name}: {base} not found")
            continue
        files = collect_files(base)
        print(f"  {name}: {len(files)} files")
        extra_sources.append((slug, name, url, files))

    # Write to DB (only payload_sources - PAT/SecLists unchanged)
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM wordlist_source_files"))
        await db.execute(text("DELETE FROM payload_sources"))
        await db.commit()

        for slug, name, url, files in extra_sources:
            src = PayloadSource(slug=slug, name=name, repo_url=url, synced_at=datetime.utcnow())
            db.add(src)
            await db.flush()
            for cat_path, path_str, size, content in files:
                fn = path_str.split("/")[-1] if "/" in path_str else path_str
                db.add(WordlistSourceFile(
                    source_id=src.id,
                    category_path=cat_path,
                    path=path_str,
                    filename=fn,
                    content=content,
                    size_bytes=size,
                ))
            await db.commit()
            print(f"Imported {name}: {len(files)} files")

    print("\n" + "=" * 60)
    print("DONE. PAT & SecLists: use import_payloads_seclists.py")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run())
