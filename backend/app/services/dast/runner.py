"""DAST scan runner: run_dast_scan, progress, ALL_CHECKS registry."""
import json
import logging
import time
from typing import Callable

from .base import DastResult, resolve_base_url, set_scan_ctx, ScanContext
from .discovery import check_directory_discovery
from .checks import (
    check_security_headers,
    check_ssl_tls,
    check_cookie_security,
    check_cors,
    check_info_disclosure,
    check_http_methods,
    check_tech_fingerprint,
    check_sitemap_xml,
    check_robots_txt,
    check_directory_listing,
    check_open_redirect,
    check_rate_limiting,
    check_xss_basic,
    check_sqli_error,
    check_api_docs_exposure,
    check_host_header_injection,
    check_crlf_injection,
    check_sensitive_data,
    check_sri,
    check_cache_control,
    check_form_autocomplete,
    check_backup_files,
    check_security_txt,
    check_http_redirect_https,
    check_hsts_preload,
    check_version_headers,
    check_coop_coep,
    check_weak_referrer,
    check_debug_response,
    check_dotenv_git,
    check_content_type_sniffing,
    check_clickjacking,
    check_trace_xst,
    check_expect_ct,
    check_permissions_policy,
    check_xss_protection_header,
    check_csp_reporting,
    check_server_timing,
    check_via_header,
    check_x_forwarded_disclosure,
    check_allow_dangerous,
    check_corp,
    check_clear_site_data,
    check_cache_age,
    check_upgrade_insecure,
    check_cookie_prefix,
    check_redirect_chain,
    check_timing_allow_origin,
    check_alt_svc,
    check_hsts_subdomains,
    check_content_disposition,
    check_pragma_no_cache,
    check_padding_oracle,
)

logger = logging.getLogger(__name__)

ALL_CHECKS = [
    ("security_headers", check_security_headers),
    ("ssl_tls", check_ssl_tls),
    ("cookie_security", check_cookie_security),
    ("cors", check_cors),
    ("info_disclosure", check_info_disclosure),
    ("tech_fingerprint", check_tech_fingerprint),
    ("sitemap_xml", check_sitemap_xml),
    ("http_methods", check_http_methods),
    ("robots_txt", check_robots_txt),
    ("directory_listing", check_directory_listing),
    ("open_redirect", check_open_redirect),
    ("rate_limiting", check_rate_limiting),
    ("xss_basic", check_xss_basic),
    ("sqli_error", check_sqli_error),
    ("api_docs_exposure", check_api_docs_exposure),
    ("host_header_injection", check_host_header_injection),
    ("crlf_injection", check_crlf_injection),
    ("sensitive_data", check_sensitive_data),
    ("sri", check_sri),
    ("cache_control", check_cache_control),
    ("form_autocomplete", check_form_autocomplete),
    ("backup_files", check_backup_files),
    ("directory_discovery", check_directory_discovery),
    ("security_txt", check_security_txt),
    ("http_redirect_https", check_http_redirect_https),
    ("hsts_preload", check_hsts_preload),
    ("version_headers", check_version_headers),
    ("coop_coep", check_coop_coep),
    ("weak_referrer", check_weak_referrer),
    ("debug_response", check_debug_response),
    ("dotenv_git", check_dotenv_git),
    ("content_type_sniffing", check_content_type_sniffing),
    ("clickjacking", check_clickjacking),
    ("trace_xst", check_trace_xst),
    ("expect_ct", check_expect_ct),
    ("permissions_policy", check_permissions_policy),
    ("xss_protection_header", check_xss_protection_header),
    ("csp_reporting", check_csp_reporting),
    ("server_timing", check_server_timing),
    ("via_header", check_via_header),
    ("x_forwarded_disclosure", check_x_forwarded_disclosure),
    ("allow_dangerous", check_allow_dangerous),
    ("corp", check_corp),
    ("clear_site_data", check_clear_site_data),
    ("cache_age", check_cache_age),
    ("upgrade_insecure", check_upgrade_insecure),
    ("cookie_prefix", check_cookie_prefix),
    ("redirect_chain", check_redirect_chain),
    ("timing_allow_origin", check_timing_allow_origin),
    ("alt_svc", check_alt_svc),
    ("hsts_subdomains", check_hsts_subdomains),
    ("content_disposition", check_content_disposition),
    ("pragma_no_cache", check_pragma_no_cache),
    ("padding_oracle", check_padding_oracle),
]

_redis_sync = None
_redis_lock = __import__("threading").Lock()
DAST_PROGRESS_TTL = 3600


def _get_redis_sync():
    global _redis_sync
    if _redis_sync is None:
        from app.core.config import get_settings
        import redis as redis_lib
        _redis_sync = redis_lib.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_sync


def _dast_progress_set(scan_id: str, data: dict) -> None:
    key = f"dast:scan:{scan_id}"
    try:
        r = _get_redis_sync()
        r.setex(key, DAST_PROGRESS_TTL, json.dumps(data, default=str))
    except Exception as e:
        logger.warning("DAST progress redis set failed: %s", e)


def _dast_progress_get(scan_id: str) -> dict | None:
    key = f"dast:scan:{scan_id}"
    try:
        r = _get_redis_sync()
        raw = r.get(key)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning("DAST progress redis get failed: %s", e)
    return None


def run_dast_scan(
    target_url: str,
    checks: list[str] | None = None,
    progress_scan_id: str | None = None,
    progress_meta: dict | None = None,
    on_progress: Callable | None = None,
) -> dict:
    """Run DAST scan with optional progress callback."""
    results = []
    selected = ALL_CHECKS if not checks else [(n, f) for n, f in ALL_CHECKS if n in checks]
    total = len(selected)

    def _emit(index: int, check_name: str, result_dict: dict | None) -> None:
        if on_progress:
            on_progress(index, total, check_name, result_dict)
        if progress_scan_id:
            entry = {
                "status": "completed" if index >= total else "running",
                "current_index": index,
                "current_check": check_name if index < total else None,
                "completed_count": index,
                "total": total,
                "results": results,
                "last_updated": time.time(),
            }
            if progress_meta:
                entry.update(progress_meta)
            _dast_progress_set(progress_scan_id, entry)

    resolved = resolve_base_url(target_url)
    effective_url = (resolved or target_url).rstrip("/") or target_url
    set_scan_ctx(ScanContext(resolved))

    start = time.time()
    try:
        for i, (name, check_fn) in enumerate(selected):
            if progress_scan_id:
                cur = _dast_progress_get(progress_scan_id)
                if cur:
                    cur["current_check"] = name
                    cur["last_updated"] = time.time()
                    _dast_progress_set(progress_scan_id, cur)
            try:
                r = check_fn(effective_url)
                rd = r.to_dict()
                results.append(rd)
                _emit(i + 1, name, rd)
            except Exception as e:
                rd = DastResult(
                    check_id=f"DAST-ERR-{name}",
                    title=f"Error in {name}",
                    status="error",
                    description=str(e)[:200],
                ).to_dict()
                results.append(rd)
                _emit(i + 1, name, rd)
    finally:
        set_scan_ctx(None)

    duration = round(time.time() - start, 2)
    passed = sum(1 for r in results if r["status"] == "passed")
    failed = sum(1 for r in results if r["status"] == "failed")
    errors = sum(1 for r in results if r["status"] == "error")
    final = {
        "target_url": target_url,
        "total_checks": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "duration_seconds": duration,
        "results": results,
    }
    if progress_scan_id:
        _dast_progress_set(progress_scan_id, {
            "status": "completed",
            "current_check": None,
            "completed_count": total,
            "total": total,
            "results": results,
            "last_updated": time.time(),
            "target_url": target_url,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "duration_seconds": duration,
        })
    return final


def get_dast_progress(scan_id: str) -> dict | None:
    """Return current progress for a scan."""
    return _dast_progress_get(scan_id)


def list_dast_progress(max_age_sec: float = 3600) -> list[dict]:
    """Return all scans (active + recent)."""
    try:
        r = _get_redis_sync()
        keys = r.keys("dast:scan:*")
        out = []
        now = time.time()
        for key in keys or []:
            raw = r.get(key)
            if raw:
                v = json.loads(raw)
                if isinstance(v, dict) and (now - v.get("last_updated", 0)) <= max_age_sec:
                    sid = key.replace("dast:scan:", "")
                    out.append({"scan_id": sid, **v})
        return out
    except Exception as e:
        logger.warning("list_dast_progress failed: %s", e)
        return []
