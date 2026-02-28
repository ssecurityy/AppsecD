#!/usr/bin/env python3
"""Run full payload & test case import for Navigator.
Prerequisites: PAT + SecLists in data/, migrations done, seed_db.py run.
Usage: cd backend && source venv/bin/activate && python scripts/setup_payloads.py
"""
import asyncio
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
SCRIPTS = [
    "import_payloads_seclists.py",
    "sync_all_payloads.py",
    "import_wstg_test_cases.py",
]


def main():
    print("=" * 60)
    print("NAVIGATOR — Full Payload & Test Case Setup")
    print("=" * 60)
    for i, script in enumerate(SCRIPTS, 1):
        path = BACKEND / "scripts" / script
        if not path.exists():
            print(f"[{i}/{len(SCRIPTS)}] SKIP {script} (not found)")
            continue
        print(f"\n[{i}/{len(SCRIPTS)}] Running {script}...\n")
        sys.stdout.flush()
        result = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(BACKEND),
            env={**__import__("os").environ, "PYTHONPATH": str(BACKEND)},
        )
        if result.returncode != 0:
            print(f"FAILED: {script} exited with {result.returncode}")
            sys.exit(result.returncode)
    print("\n" + "=" * 60)
    print("Done. Payloads, wordlists, and WSTG test cases are in PostgreSQL.")
    print("=" * 60)


if __name__ == "__main__":
    main()
