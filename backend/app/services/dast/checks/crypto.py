"""DAST checks: padding oracle (WSTG-CRYP-02)."""
import base64
import time
from urllib.parse import urlparse

import httpx

from ..base import DastResult, safe_get, safe_request, BROWSER_HEADERS, USER_AGENTS

PADDING_ORACLE_SIGNATURES = [
    "padding",
    "decryption",
    "cipher",
    "invalid padding",
    "bad decrypt",
    "padding verification failed",
]


def _is_base64_block_cipher_candidate(val: str) -> tuple[bool, int]:
    if not val or len(val) < 16:
        return False, 0
    try:
        raw = base64.urlsafe_b64decode(val + "==")
        if len(raw) < 8:
            return False, 0
        if len(raw) % 16 == 0:
            return True, 16
        if len(raw) % 8 == 0:
            return True, 8
        return False, 0
    except Exception:
        try:
            raw = base64.b64decode(val)
            if len(raw) < 8:
                return False, 0
            if len(raw) % 16 == 0:
                return True, 16
            if len(raw) % 8 == 0:
                return True, 8
            return False, 0
        except Exception:
            return False, 0


def _flip_bit(data: bytearray, idx: int) -> None:
    if 0 <= idx < len(data):
        data[idx] ^= 1


def _encode_cookie_val(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii", errors="replace").rstrip("=")


def _response_fingerprint(resp: httpx.Response) -> str:
    body = (resp.text or "").lower()
    snippets = []
    for sig in PADDING_ORACLE_SIGNATURES:
        if sig in body:
            snippets.append(sig[:20])
    return f"{resp.status_code}|{len(resp.content)}|{','.join(sorted(snippets))}"


def check_padding_oracle(target_url: str) -> DastResult:
    """Check for padding oracle (WSTG-CRYP-02)."""
    result = DastResult(
        check_id="DAST-CRYP-02",
        title="Padding Oracle (WSTG-CRYP-02)",
        owasp_ref="WSTG-CRYP-02",
        cwe_id="CWE-209",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    candidates: list[tuple[str, str, int]] = []
    cookies = resp.headers.get_list("set-cookie") or []
    for cookie_str in cookies:
        if "=" not in cookie_str:
            continue
        name = cookie_str.split("=")[0].strip()
        val_part = cookie_str.split("=", 1)[1]
        if ";" in val_part:
            val_part = val_part.split(";")[0].strip()
        val = val_part.strip()
        valid, blen = _is_base64_block_cipher_candidate(val)
        if valid and blen:
            candidates.append((name, val, blen))

    if not candidates:
        result.status = "passed"
        result.description = "No encrypted client-side data found to test"
        result.details = {"cookies_checked": len(cookies), "candidates": 0}
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())[:2000]
        result.remediation = "Ensure encrypted client data uses integrity verification (HMAC, GCM/CCM)."
        return result

    padding_oracle_found = False
    evidence_parts: list[str] = []
    tested_cookie = ""

    for cname, cval, block_len in candidates[:3]:
        try:
            raw = base64.b64decode(cval)
        except Exception:
            try:
                raw = base64.urlsafe_b64decode(cval + "==")
            except Exception:
                continue
        if len(raw) < block_len * 2:
            continue

        tested_cookie = cname
        indices_to_flip = [
            len(raw) - block_len - 1,
            len(raw) - 2 * block_len - 1,
        ]
        fingerprints: set[str] = set()
        has_padding_error = False
        base_fp = _response_fingerprint(resp)
        fingerprints.add(base_fp)

        for flip_idx in indices_to_flip:
            data = bytearray(raw)
            _flip_bit(data, flip_idx)
            tampered = _encode_cookie_val(bytes(data))
            headers = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0], "Cookie": f"{cname}={tampered}"}
            time.sleep(0.5)
            r2 = safe_request("GET", target_url, headers=headers)
            if not r2:
                continue
            fp = _response_fingerprint(r2)
            fingerprints.add(fp)
            body_lower = (r2.text or "").lower()
            for sig in PADDING_ORACLE_SIGNATURES:
                if sig in body_lower:
                    has_padding_error = True
                    evidence_parts.append(f"{cname}: padding error signature '{sig}'")
                    break
            if has_padding_error:
                break

        if has_padding_error and len(fingerprints) >= 2:
            padding_oracle_found = True
            break
        if len(fingerprints) >= 3:
            evidence_parts.append(f"{cname}: 3+ distinct responses (possible oracle)")
            padding_oracle_found = True
            break

    result.details = {"candidates_tested": len(candidates[:3]), "tested_cookie": tested_cookie}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}\nCookie: {tested_cookie}=..."
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())[:2000]

    if padding_oracle_found:
        result.status = "failed"
        result.severity = "medium"
        result.description = "Padding oracle likely present"
        result.evidence = "; ".join(evidence_parts) if evidence_parts else f"Cookie '{tested_cookie}' showed distinct responses"
        result.remediation = "Add integrity verification (HMAC) before decrypt. Use authenticated encryption (GCM, CCM)."
        result.reproduction_steps = (
            f"1. GET {target_url} to obtain encrypted cookie\n"
            "2. Decode base64, flip LSB of second-to-last block\n"
            "3. Re-encode and send with tampered Cookie header\n"
            "4. Compare response: padding-specific error indicates oracle"
        )
    else:
        result.status = "passed"
        result.description = "No padding oracle detected"
        result.remediation = "Ensure encrypted client data uses HMAC or GCM/CCM."

    return result
