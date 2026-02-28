#!/usr/bin/env python3
"""Import OWASP WSTG test cases from markdown into test_cases table.
Run after: git clone OWASP/wstg to data/OWASP-wstg (or sync_all_payloads.py).
Requires: categories and seed test cases may exist; this ADDS WSTG cases.
"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.category import Category
from app.models.test_case import TestCase

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
WSTG_BASE = DATA_DIR / "OWASP-wstg" / "document" / "4-Web_Application_Security_Testing"

# Map WSTG section prefix (01, 02, ...) to Navigator phase
WSTG_TO_PHASE = {
    "01": "recon",           # Information_Gathering
    "02": "infra",           # Configuration_and_Deployment
    "03": "auth",            # Identity_Management
    "04": "auth",            # Authentication
    "05": "post_auth",       # Authorization
    "06": "auth",            # Session_Management
    "07": "post_auth",       # Input_Validation
    "08": "infra",          # Error_Handling
    "09": "transport",       # Cryptography
    "10": "business",       # Business_Logic
    "11": "client",         # Client-side
    "12": "api",            # API_Testing
}


def _parse_md(path: Path) -> dict | None:
    """Parse WSTG markdown into test case fields."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    if not text.strip():
        return None

    lines = text.split("\n")
    title = ""
    wstg_id = ""
    summary = []
    how_to_test = []
    in_summary = False
    in_how = False

    for i, line in enumerate(lines):
        if line.startswith("# "):
            title = line[2:].strip()
        elif "|WSTG-" in line:
            m = re.search(r"WSTG-[A-Z]+-\d+(?:\.\d+)?", line)
            if m:
                wstg_id = m.group(0)
        elif line.strip() == "## Summary":
            in_summary = True
            in_how = False
        elif line.strip() == "## How to Test":
            in_summary = False
            in_how = True
        elif line.strip().startswith("## "):
            in_summary = False
            in_how = False
        elif in_summary and line.strip():
            summary.append(line.strip())
        elif in_how and line.strip() and not line.strip().startswith("#"):
            if len(how_to_test) < 5000:  # Cap length
                how_to_test.append(line)

    if not title:
        return None

    return {
        "title": title,
        "module_id": (wstg_id or path.stem)[:20],
        "description": " ".join(summary)[:2000] if summary else None,
        "how_to_test": "\n".join(how_to_test)[:8000] if how_to_test else None,
        "references": [{"title": "OWASP WSTG", "url": "https://owasp.org/www-project-web-security-testing-guide/"}],
    }


def iter_wstg_tests():
    """Yield (phase, parsed_dict) for each WSTG test file."""
    if not WSTG_BASE.exists():
        return
    for section_dir in sorted(WSTG_BASE.iterdir()):
        if not section_dir.is_dir() or section_dir.name.startswith("."):
            continue
        prefix = section_dir.name[:2] if len(section_dir.name) >= 2 else "00"
        phase = WSTG_TO_PHASE.get(prefix, "post_auth")
        for md_file in section_dir.rglob("*.md"):
            if md_file.name == "README.md":
                continue
            parsed = _parse_md(md_file)
            if parsed:
                yield phase, parsed


async def run():
    if not WSTG_BASE.exists():
        print(f"OWASP WSTG not found at {WSTG_BASE}. Run sync_all_payloads.py first.")
        return

    tests = list(iter_wstg_tests())
    print(f"Found {len(tests)} WSTG test cases to import")

    async with AsyncSessionLocal() as db:
        cats = (await db.execute(select(Category))).scalars().all()
        cat_map = {c.phase: c for c in cats}
        if not cat_map:
            print("No categories found. Run seed_db.py first.")
            return

        added = 0
        for phase, data in tests:
            cat = cat_map.get(phase)
            if not cat:
                cat = cat_map.get("post_auth")
            tc = TestCase(
                category_id=cat.id,
                module_id=data.get("module_id"),
                title=data["title"],
                description=data.get("description"),
                owasp_ref="WSTG",
                phase=phase,
                how_to_test=data.get("how_to_test"),
                references=data.get("references", []),
                tags=["wstg", "owasp"],
            )
            db.add(tc)
            added += 1
        await db.commit()
        print(f"Imported {added} OWASP WSTG test cases")


if __name__ == "__main__":
    asyncio.run(run())
