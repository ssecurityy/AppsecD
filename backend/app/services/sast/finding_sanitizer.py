"""Sanitize SAST finding dicts so all string fields fit DB column limits.

Prevents StringDataRightTruncationError when inserting into sast_findings.
"""
# Column limits for sast_findings (must match app/models/sast_scan.py)
LIMITS = {
    "rule_id": 255,
    "rule_source": 30,
    "severity": 20,
    "confidence": 20,
    "title": 500,
    "file_path": 1000,
    "cwe_id": 20,
    "owasp_category": 255,  # widened from 50 to avoid truncation from rule metadata
    "fingerprint": 64,
    "status": 30,
    "suppression_type": 30,
}
# Reasonable caps for Text fields to avoid mis-assignment or runaway content
TEXT_CAP = 2_000_000  # ~2MB per text field


def _trunc(s: str | None, max_len: int) -> str | None:
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= max_len:
        return s
    return s[:max_len]


def sanitize_finding_for_db(f: dict) -> dict:
    """Return a copy of the finding dict with all string fields truncated to DB limits."""
    out = dict(f)
    for key, max_len in LIMITS.items():
        if key in out and out[key] is not None:
            out[key] = _trunc(out[key], max_len)
    # Cap Text-like fields in case of mis-mapping or huge content
    for key in ("description", "message", "code_snippet", "fix_suggestion", "fixed_code"):
        if key in out and out[key] is not None:
            val = out[key]
            if isinstance(val, str) and len(val) > TEXT_CAP:
                out[key] = val[:TEXT_CAP]
    # Ensure ai_analysis is dict or None for JSONB
    if "ai_analysis" in out and out["ai_analysis"] is not None:
        if not isinstance(out["ai_analysis"], dict):
            out["ai_analysis"] = None
    return out
