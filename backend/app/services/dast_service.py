"""DAST Automation Engine — re-exports from app.services.dast package.

Modular structure:
  - dast/base.py       — DastResult, ScanContext, HTTP helpers
  - dast/wordlists.py  — Wordlist loading (IntruderPayloads + SecLists)
  - dast/discovery.py  — Directory discovery, ffuf, httpx fallback
  - dast/checks/       — Per-domain check modules (headers, ssl, recon, injection, etc.)
  - dast/runner.py     — run_dast_scan, ALL_CHECKS, progress
"""
from app.services.dast import (
    DastResult,
    run_dast_scan,
    get_dast_progress,
    list_dast_progress,
    ALL_CHECKS,
    _dast_progress_set,
    _dast_progress_get,
    run_ffuf_full_scan,
    run_ffuf_exhaustive_scan,
)

__all__ = [
    "DastResult",
    "run_dast_scan",
    "get_dast_progress",
    "list_dast_progress",
    "ALL_CHECKS",
    "_dast_progress_set",
    "_dast_progress_get",
    "run_ffuf_full_scan",
    "run_ffuf_exhaustive_scan",
]
