"""DAST export service — Burp Suite XML, JSON, CSV, HAR formats.

Generates export-compatible files from scan findings and crawl results.
Burp XML follows the Burp Suite issue export schema for import compatibility.
"""
import base64
import csv
import hashlib
import io
import json
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString

logger = logging.getLogger(__name__)

# Burp issue type mapping
BURP_ISSUE_TYPES = {
    "sqli": {"type_index": "1049088", "name": "SQL injection"},
    "xss": {"type_index": "2097920", "name": "Cross-site scripting (reflected)"},
    "xss_stored": {"type_index": "2097936", "name": "Cross-site scripting (stored)"},
    "csrf": {"type_index": "2098944", "name": "Cross-site request forgery"},
    "lfi": {"type_index": "1049344", "name": "File path traversal"},
    "ssrf": {"type_index": "1051392", "name": "Server-side request forgery"},
    "cmdi": {"type_index": "1049600", "name": "OS command injection"},
    "ssti": {"type_index": "1049856", "name": "Server-side template injection"},
    "xxe": {"type_index": "1050112", "name": "XML external entity injection"},
    "idor": {"type_index": "2098176", "name": "Access control - insecure direct object reference"},
    "open_redirect": {"type_index": "5244416", "name": "Open redirection"},
    "cors": {"type_index": "2098688", "name": "Cross-origin resource sharing"},
    "jwt": {"type_index": "2099200", "name": "JWT authentication bypass"},
    "info_disclosure": {"type_index": "6291968", "name": "Information disclosure"},
    "header_missing": {"type_index": "6292096", "name": "Missing security header"},
    "ssl_issue": {"type_index": "16777472", "name": "SSL/TLS issue"},
    "cookie_issue": {"type_index": "5244928", "name": "Cookie without appropriate flags"},
    "deserialization": {"type_index": "1050368", "name": "Insecure deserialization"},
    "default": {"type_index": "134217728", "name": "Application vulnerability"},
}

SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Information",
}

CONFIDENCE_MAP = {
    "critical": "Certain",
    "high": "Firm",
    "medium": "Firm",
    "low": "Tentative",
    "info": "Tentative",
}


def export_findings_burp_xml(findings: list[dict], scan_metadata: dict | None = None) -> str:
    """Generate Burp Suite compatible XML from findings."""
    root = Element("issues")
    root.set("burpVersion", "2024.1")
    root.set("exportTime", datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

    for idx, finding in enumerate(findings):
        issue = SubElement(root, "issue")

        serial = SubElement(issue, "serialNumber")
        serial.text = str(abs(hash(finding.get("id", str(idx)))) % (10**16))

        issue_type = _map_to_burp_type(finding)
        type_el = SubElement(issue, "type")
        type_el.text = issue_type["type_index"]

        name = SubElement(issue, "name")
        name.text = finding.get("title", "Unknown Vulnerability")

        # Host
        affected_url = finding.get("affected_url", "")
        parsed = urlparse(affected_url) if affected_url else None
        host = SubElement(issue, "host")
        if parsed and parsed.netloc:
            host.text = f"{parsed.scheme}://{parsed.netloc}"
            host.set("ip", "")
        else:
            target = scan_metadata.get("target_url", "") if scan_metadata else ""
            host.text = target
            host.set("ip", "")

        path_el = SubElement(issue, "path")
        path_el.text = parsed.path if parsed else "/"

        location = SubElement(issue, "location")
        param = finding.get("affected_parameter", "")
        loc_text = parsed.path if parsed else "/"
        if param:
            loc_text += f" [{param}]"
        location.text = loc_text

        severity_el = SubElement(issue, "severity")
        severity_el.text = SEVERITY_MAP.get(finding.get("severity", "info"), "Information")

        confidence_el = SubElement(issue, "confidence")
        confidence_el.text = CONFIDENCE_MAP.get(finding.get("severity", "info"), "Tentative")

        # Background
        bg = SubElement(issue, "issueBackground")
        bg.text = _cdata(finding.get("description", ""))

        remediation_bg = SubElement(issue, "remediationBackground")
        remediation_bg.text = _cdata(finding.get("recommendation", ""))

        detail = SubElement(issue, "issueDetail")
        detail_parts = []
        if finding.get("reproduction_steps"):
            detail_parts.append(f"<b>Reproduction Steps:</b><br/>{_escape_html(finding['reproduction_steps'])}")
        if finding.get("impact"):
            detail_parts.append(f"<b>Impact:</b><br/>{_escape_html(finding['impact'])}")
        if finding.get("cwe_id"):
            detail_parts.append(f"<b>CWE:</b> {finding['cwe_id']}")
        if finding.get("owasp_category"):
            detail_parts.append(f"<b>OWASP:</b> {finding['owasp_category']}")
        if finding.get("cvss_score"):
            detail_parts.append(f"<b>CVSS:</b> {finding['cvss_score']}")
        detail.text = _cdata("<br/>".join(detail_parts))

        remediation_detail = SubElement(issue, "remediationDetail")
        remediation_detail.text = ""

        # Request/Response
        if finding.get("request") or finding.get("response"):
            rr = SubElement(issue, "requestresponse")
            req = SubElement(rr, "request")
            req.set("base64", "true")
            req.text = base64.b64encode((finding.get("request") or "").encode()).decode()

            resp_el = SubElement(rr, "response")
            resp_el.set("base64", "true")
            resp_el.text = base64.b64encode((finding.get("response") or "").encode()).decode()

    xml_str = tostring(root, encoding="unicode")
    try:
        pretty = parseString(xml_str).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
        # Remove extra XML declaration if present
        if pretty.startswith("<?xml"):
            pretty = pretty.split("?>", 1)[1].strip()
        return f'<?xml version="1.0" encoding="utf-8"?>\n{pretty}'
    except Exception:
        return f'<?xml version="1.0" encoding="utf-8"?>\n{xml_str}'


def export_crawl_burp_xml(crawl_results: list[dict]) -> str:
    """Generate Burp-compatible sitemap XML from crawl data."""
    root = Element("items")
    root.set("burpVersion", "2024.1")
    root.set("exportTime", datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

    for item in crawl_results:
        url = item.get("url", "")
        if not url:
            continue

        parsed = urlparse(url)
        el = SubElement(root, "item")

        time_el = SubElement(el, "time")
        time_el.text = datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")

        url_el = SubElement(el, "url")
        url_el.text = _cdata(url)

        host_el = SubElement(el, "host")
        host_el.text = parsed.netloc
        host_el.set("ip", "")

        port_el = SubElement(el, "port")
        port_el.text = str(parsed.port or (443 if parsed.scheme == "https" else 80))

        protocol_el = SubElement(el, "protocol")
        protocol_el.text = parsed.scheme

        method_el = SubElement(el, "method")
        method_el.text = item.get("method", "GET")

        path_el = SubElement(el, "path")
        path_el.text = _cdata(parsed.path or "/")

        ext_el = SubElement(el, "extension")
        path_parts = (parsed.path or "").rsplit(".", 1)
        ext_el.text = path_parts[1] if len(path_parts) > 1 else ""

        req_el = SubElement(el, "request")
        req_el.set("base64", "true")
        req_text = f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n"
        req_el.text = base64.b64encode(req_text.encode()).decode()

        status_el = SubElement(el, "status")
        status_el.text = str(item.get("status_code", 200))

        resp_len_el = SubElement(el, "responselength")
        resp_len_el.text = str(item.get("content_length", 0))

        mime_el = SubElement(el, "mimetype")
        mime_el.text = item.get("content_type", "text/html")

        resp_el = SubElement(el, "response")
        resp_el.set("base64", "true")
        resp_el.text = ""

        comment_el = SubElement(el, "comment")
        comment_el.text = item.get("title", "")

    xml_str = tostring(root, encoding="unicode")
    try:
        pretty = parseString(xml_str).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
        if pretty.startswith("<?xml"):
            pretty = pretty.split("?>", 1)[1].strip()
        return f'<?xml version="1.0" encoding="utf-8"?>\n{pretty}'
    except Exception:
        return f'<?xml version="1.0" encoding="utf-8"?>\n{xml_str}'


def export_findings_json(findings: list[dict], scan_metadata: dict | None = None) -> dict:
    """Generic JSON export of all findings with full evidence."""
    return {
        "export_format": "navigator_dast_v1",
        "exported_at": datetime.utcnow().isoformat(),
        "scan_metadata": scan_metadata or {},
        "total_findings": len(findings),
        "findings_by_severity": _count_by_severity(findings),
        "findings": [
            {
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "severity": f.get("severity", "info"),
                "status": f.get("status", "open"),
                "affected_url": f.get("affected_url", ""),
                "affected_parameter": f.get("affected_parameter", ""),
                "cwe_id": f.get("cwe_id", ""),
                "cvss_score": f.get("cvss_score", ""),
                "cvss_vector": f.get("cvss_vector", ""),
                "owasp_category": f.get("owasp_category", ""),
                "request": f.get("request", ""),
                "response": f.get("response", ""),
                "evidence_urls": f.get("evidence_urls", []),
                "reproduction_steps": f.get("reproduction_steps", ""),
                "impact": f.get("impact", ""),
                "recommendation": f.get("recommendation", ""),
                "references": f.get("references", []),
                "cve_ids": f.get("cve_ids", []),
                "created_at": f.get("created_at", ""),
            }
            for f in findings
        ],
    }


def export_findings_csv(findings: list[dict]) -> str:
    """CSV export for spreadsheet import."""
    output = io.StringIO()
    fieldnames = [
        "id", "title", "severity", "status", "affected_url", "affected_parameter",
        "cwe_id", "cvss_score", "owasp_category", "description", "recommendation",
        "reproduction_steps", "impact", "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = {k: (f.get(k, "") or "") for k in fieldnames}
        # Truncate long fields for CSV
        for key in ["description", "recommendation", "reproduction_steps", "impact"]:
            if len(row.get(key, "")) > 5000:
                row[key] = row[key][:5000] + "..."
        writer.writerow(row)
    return output.getvalue()


def export_har(requests_responses: list[dict]) -> dict:
    """HAR (HTTP Archive) format export for browser devtools/proxies."""
    entries = []
    for rr in requests_responses:
        entry = {
            "startedDateTime": rr.get("timestamp", datetime.utcnow().isoformat()),
            "time": rr.get("elapsed_ms", 0),
            "request": {
                "method": rr.get("method", "GET"),
                "url": rr.get("url", ""),
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in rr.get("request_headers", {}).items()],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(rr.get("request_body", "")),
                "postData": {
                    "mimeType": rr.get("request_content_type", ""),
                    "text": rr.get("request_body", ""),
                } if rr.get("request_body") else None,
            },
            "response": {
                "status": rr.get("status_code", 0),
                "statusText": rr.get("status_text", ""),
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in rr.get("response_headers", {}).items()],
                "cookies": [],
                "content": {
                    "size": len(rr.get("response_body", "")),
                    "mimeType": rr.get("response_content_type", "text/html"),
                    "text": rr.get("response_body", "")[:50000],  # Limit size
                },
                "redirectURL": rr.get("redirect_url", ""),
                "headersSize": -1,
                "bodySize": len(rr.get("response_body", "")),
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": rr.get("elapsed_ms", 0),
                "receive": 0,
            },
        }
        # Remove None postData
        if entry["request"]["postData"] is None:
            del entry["request"]["postData"]
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "Navigator DAST",
                "version": "1.0",
            },
            "entries": entries,
        }
    }


def _map_to_burp_type(finding: dict) -> dict:
    """Map a finding to a Burp issue type."""
    title = (finding.get("title") or "").lower()
    cwe = finding.get("cwe_id", "")

    mapping = [
        (["sql injection", "sqli", "cwe-89"], "sqli"),
        (["cross-site scripting", "xss", "cwe-79"], "xss"),
        (["csrf", "cross-site request forgery", "cwe-352"], "csrf"),
        (["path traversal", "local file", "lfi", "cwe-22"], "lfi"),
        (["ssrf", "server-side request", "cwe-918"], "ssrf"),
        (["command injection", "cwe-78"], "cmdi"),
        (["template injection", "ssti", "cwe-1336"], "ssti"),
        (["xxe", "xml external", "cwe-611"], "xxe"),
        (["idor", "insecure direct", "cwe-639"], "idor"),
        (["open redirect", "cwe-601"], "open_redirect"),
        (["cors", "cwe-942"], "cors"),
        (["jwt", "cwe-347"], "jwt"),
        (["deserialization", "cwe-502"], "deserialization"),
        (["disclosure", "leak", "exposure", "cwe-200"], "info_disclosure"),
        (["header", "csp", "hsts"], "header_missing"),
        (["ssl", "tls", "certificate"], "ssl_issue"),
        (["cookie"], "cookie_issue"),
    ]

    for keywords, key in mapping:
        for kw in keywords:
            if kw in title or kw in cwe.lower():
                return BURP_ISSUE_TYPES[key]

    return BURP_ISSUE_TYPES["default"]


def _count_by_severity(findings: list[dict]) -> dict:
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _cdata(text: str) -> str:
    """Wrap text for XML safety."""
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
