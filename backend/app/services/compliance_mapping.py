"""Compliance framework mapping: OWASP, CWE, MITRE ATT&CK, ISO 27001, NIST 800-53."""
from typing import Any

# CWE -> (MITRE ATT&CK, ISO 27001, NIST 800-53)
CWE_COMPLIANCE = {
    "CWE-79": ("T1059.007", "A.14.1.5", "SI-11"),
    "CWE-89": ("T1190", "A.14.1.3", "SI-10"),
    "CWE-352": ("T1539", "A.14.1.5", "AC-4"),
    "CWE-78": ("T1059", "A.14.1.3", "SI-10"),
    "CWE-22": ("T1083", "A.12.1.4", "AC-6"),
    "CWE-287": ("T1078", "A.9.4.1", "AC-2"),
    "CWE-611": ("T1220", "A.12.1.4", "SI-10"),
    "CWE-918": ("T1071", "A.12.1.2", "SC-7"),
    "CWE-639": ("T1078", "A.9.4.2", "AC-4"),
    "CWE-601": ("T1566", "A.14.1.5", "AC-4"),
    "CWE-347": ("T1552.001", "A.9.4.1", "IA-5"),
    "CWE-1336": ("T1059", "A.14.1.3", "SI-10"),
}

# OWASP Top 10 2021 -> frameworks
OWASP_COMPLIANCE = {
    "A01": {"mitre": "T1190", "iso": "A.14.1.3", "nist": "SI-10"},
    "A02": {"mitre": "T1078", "iso": "A.9.4.1", "nist": "IA-5"},
    "A03": {"mitre": "T1190", "iso": "A.14.1.3", "nist": "SI-10"},
    "A04": {"mitre": "T1535", "iso": "A.12.1.2", "nist": "SC-7"},
    "A05": {"mitre": "T1566", "iso": "A.12.2.1", "nist": "AC-17"},
    "A06": {"mitre": "T1078", "iso": "A.9.4.2", "nist": "AC-4"},
    "A07": {"mitre": "T1190", "iso": "A.14.1.5", "nist": "SI-11"},
    "A08": {"mitre": "T1552", "iso": "A.14.1.3", "nist": "SI-10"},
    "A09": {"mitre": "T1538", "iso": "A.12.4.1", "nist": "SA-15"},
    "A10": {"mitre": "T1190", "iso": "A.12.1.4", "nist": "SI-10"},
}


def get_compliance_mapping(cwe_id: str = None, owasp_category: str = None) -> dict:
    """Get compliance framework mappings for a finding."""
    result = {"owasp": None, "cwe": cwe_id, "mitre_attack": None, "iso_27001": None, "nist_800_53": None}
    if cwe_id and cwe_id in CWE_COMPLIANCE:
        mitre, iso, nist = CWE_COMPLIANCE[cwe_id]
        result["mitre_attack"] = mitre
        result["iso_27001"] = iso
        result["nist_800_53"] = nist
    if owasp_category:
        result["owasp"] = owasp_category
        okey = owasp_category.upper().replace(" ", "")[:3]  # A01, A02, etc.
        if okey in OWASP_COMPLIANCE:
            m = OWASP_COMPLIANCE[okey]
            if not result["mitre_attack"]:
                result["mitre_attack"] = m["mitre"]
            if not result["iso_27001"]:
                result["iso_27001"] = m["iso"]
            if not result["nist_800_53"]:
                result["nist_800_53"] = m["nist"]
    return result
