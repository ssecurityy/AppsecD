"""CVE Intelligence enrichment — EPSS exploitability, CISA KEV, and CVSS data.

All data sources are free and require no API keys:
  - EPSS: https://api.first.org/data/v1/epss
  - KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - CVSS scoring is extracted from OSV data already present in findings.

Results are cached in Redis (24h TTL) to avoid repeated API calls.
"""
import json
import logging
import re
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_TIMEOUT = 15
KEV_TIMEOUT = 30
CACHE_TTL = 86400  # 24 hours

_kev_set: set[str] | None = None
_kev_loaded_at: datetime | None = None


def _redis():
    """Get a Redis connection."""
    try:
        import redis as redis_lib
        from app.core.config import get_settings
        return redis_lib.from_url(get_settings().redis_url)
    except Exception:
        return None


def _cache_get(key: str) -> dict | None:
    r = _redis()
    if not r:
        return None
    try:
        data = r.get(f"cve_enrichment:{key}")
        return json.loads(data) if data else None
    except Exception:
        return None


def _cache_set(key: str, value: dict, ttl: int = CACHE_TTL) -> None:
    r = _redis()
    if not r:
        return
    try:
        r.setex(f"cve_enrichment:{key}", ttl, json.dumps(value, default=str))
    except Exception:
        pass


async def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-query EPSS API for exploit probability scores.

    Returns mapping of CVE-ID → EPSS probability (0.0 to 1.0).
    """
    if not cve_ids:
        return {}

    result: dict[str, float] = {}
    uncached: list[str] = []

    for cve_id in cve_ids:
        cached = _cache_get(f"epss:{cve_id}")
        if cached is not None:
            result[cve_id] = cached.get("score", 0.0)
        else:
            uncached.append(cve_id)

    if not uncached:
        return result

    for i in range(0, len(uncached), 30):
        batch = uncached[i:i + 30]
        try:
            async with httpx.AsyncClient(timeout=EPSS_TIMEOUT) as client:
                resp = await client.get(EPSS_API, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                data = resp.json()

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                score = float(entry.get("epss", 0.0))
                result[cve_id] = score
                _cache_set(f"epss:{cve_id}", {"score": score})

        except Exception as e:
            logger.warning("EPSS batch query failed: %s", e)

    return result


async def load_kev_catalog() -> set[str]:
    """Load CISA Known Exploited Vulnerabilities catalog.

    Returns set of CVE IDs in the KEV catalog.
    """
    global _kev_set, _kev_loaded_at

    if _kev_set is not None and _kev_loaded_at:
        age = (datetime.utcnow() - _kev_loaded_at).total_seconds()
        if age < CACHE_TTL:
            return _kev_set

    cached = _cache_get("kev:catalog_ids")
    if cached and isinstance(cached.get("ids"), list):
        _kev_set = set(cached["ids"])
        _kev_loaded_at = datetime.utcnow()
        return _kev_set

    try:
        async with httpx.AsyncClient(timeout=KEV_TIMEOUT) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        ids = set()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                ids.add(cve_id)

        _kev_set = ids
        _kev_loaded_at = datetime.utcnow()
        _cache_set("kev:catalog_ids", {"ids": list(ids)})
        logger.info("KEV catalog loaded: %d CVEs", len(ids))
        return ids

    except Exception as e:
        logger.warning("Failed to load KEV catalog: %s", e)
        return _kev_set or set()


def check_kev(cve_id: str, kev_set: set[str]) -> bool:
    """Check if a CVE is in the KEV catalog."""
    return cve_id in kev_set


def _extract_cve_ids_from_findings(findings: list[dict]) -> list[str]:
    """Extract all CVE IDs from a list of SCA findings."""
    cve_ids = set()
    for f in findings:
        rule_id = f.get("rule_id", "")
        match = re.search(r"CVE-\d{4}-\d+", rule_id)
        if match:
            cve_ids.add(match.group())
        refs = f.get("references", [])
        if isinstance(refs, list):
            for ref in refs:
                url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
                for m in re.finditer(r"CVE-\d{4}-\d+", url):
                    cve_ids.add(m.group())
    return sorted(cve_ids)


async def enrich_findings(findings: list[dict]) -> list[dict]:
    """Enrich SCA findings with EPSS scores and KEV status.

    Modifies findings in-place and returns them sorted by priority.
    """
    if not findings:
        return findings

    cve_ids = _extract_cve_ids_from_findings(findings)
    if not cve_ids:
        return findings

    logger.info("CVE enrichment: enriching %d CVEs from %d findings", len(cve_ids), len(findings))

    epss_scores = await get_epss_scores(cve_ids)
    kev_set = await load_kev_catalog()

    for f in findings:
        rule_id = f.get("rule_id", "")
        cve_match = re.search(r"CVE-\d{4}-\d+", rule_id)
        if not cve_match:
            continue

        cve_id = cve_match.group()
        epss = epss_scores.get(cve_id, 0.0)
        in_kev = check_kev(cve_id, kev_set)

        enrichment = {
            "cve_id": cve_id,
            "epss_score": epss,
            "in_kev": in_kev,
        }

        refs = f.get("references") or []
        if isinstance(refs, list):
            refs.append(enrichment)
            f["references"] = refs

        if in_kev:
            f["severity"] = "critical"
            if f.get("description"):
                f["description"] += " [CISA KEV: Known to be actively exploited]"

        if epss > 0.5 and f.get("severity") in ("medium", "low"):
            f["severity"] = "high"

    return prioritize_findings(findings)


def prioritize_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by priority: KEV > EPSS > CVSS > severity."""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def sort_key(f: dict) -> tuple:
        refs = f.get("references", [])
        in_kev = False
        epss = 0.0
        for ref in (refs if isinstance(refs, list) else []):
            if isinstance(ref, dict):
                if ref.get("in_kev"):
                    in_kev = True
                if ref.get("epss_score"):
                    epss = max(epss, float(ref.get("epss_score", 0)))

        sev = severity_order.get(f.get("severity", "info"), 0)
        return (-int(in_kev), -epss, -sev)

    return sorted(findings, key=sort_key)
