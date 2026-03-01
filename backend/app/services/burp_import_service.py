"""Burp Suite XML import — parse Burp XML and create findings."""
import xml.etree.ElementTree as ET
from typing import List
import base64
import re


def parse_burp_xml(xml_content: str) -> List[dict]:
    """Parse Burp Suite XML export and return list of finding dicts."""
    findings = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []
    
    severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info", "Critical": "critical"}
    
    for issue in root.findall(".//issue"):
        name = (issue.findtext("name") or "").strip()
        severity = severity_map.get((issue.findtext("severity") or "").strip(), "medium")
        host = (issue.findtext("host") or "").strip()
        path = (issue.findtext("path") or "").strip()
        detail = (issue.findtext("issueDetail") or "").strip()
        background = (issue.findtext("issueBackground") or "").strip()
        remediation_detail = (issue.findtext("remediationDetail") or "").strip()
        remediation_bg = (issue.findtext("remediationBackground") or "").strip()
        
        request_text = ""
        response_text = ""
        for req_resp in issue.findall(".//requestresponse"):
            req_el = req_resp.find("request")
            resp_el = req_resp.find("response")
            if req_el is not None and req_el.text:
                is_b64 = req_el.get("base64", "false") == "true"
                request_text = base64.b64decode(req_el.text).decode("utf-8", errors="replace") if is_b64 else req_el.text
            if resp_el is not None and resp_el.text:
                is_b64 = resp_el.get("base64", "false") == "true"
                response_text = base64.b64decode(resp_el.text).decode("utf-8", errors="replace") if is_b64 else resp_el.text
        
        description = re.sub(r'<[^>]+>', '', detail or background or "").strip()
        remediation = re.sub(r'<[^>]+>', '', remediation_detail or remediation_bg or "").strip()
        affected_url = f"{host}{path}" if host else path
        
        if name:
            findings.append({
                "title": name,
                "severity": severity,
                "description": description,
                "affected_url": affected_url,
                "recommendation": remediation,
                "request": request_text[:5000] if request_text else "",
                "response": response_text[:5000] if response_text else "",
                "status": "open",
            })
    
    return findings
