"""Report generation service — Big 4 style professional reports with screenshots."""
from datetime import datetime
from io import BytesIO
from pathlib import Path
import base64
import json
import re
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from app.services.compliance_mapping import get_compliance_mapping
from app.core.config import get_settings

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None


def _severity_order(s: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(s.lower(), 5)


def _risk_score(project: dict, findings: list) -> float:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
    total = sum(weights.get(f.get("severity", "").lower(), 0) for f in findings)
    base = 10 if project.get("failed_count", 0) > 0 else 0
    return min(100, total + base)


def _coverage_pct(project: dict) -> float:
    total = project.get("total_test_cases") or 0
    if total == 0:
        return 0.0
    tested = project.get("tested_count") or 0
    return round((tested / total) * 100, 1)


def _risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _get_evidence_file_path(project_id: str, evidence_item: dict) -> Path | None:
    """Resolve evidence item to file path. evidence_item: {filename, url}."""
    settings = get_settings()
    base = Path(settings.uploads_path) / str(project_id)
    url = evidence_item.get("url") or ""
    match = re.search(r"/evidence/([^/]+)$", url)
    if match:
        fpath = base / match.group(1)
        if fpath.exists():
            return fpath
    return None


def _evidence_to_base64(project_id: str, evidence_item: dict) -> str | None:
    """Read evidence file and return base64 data URL for images."""
    fpath = _get_evidence_file_path(project_id, evidence_item)
    if not fpath or not fpath.exists():
        return None
    ext = fpath.suffix.lower()
    if ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return None
    try:
        data = fpath.read_bytes()
        b64 = base64.b64encode(data).decode()
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}.get(ext[1:], "image/png")
        return f"data:{mime};base64,{b64}"
    except Exception:
        return None


def build_report_data(project: dict, findings: list, phases: list, project_id: str = "") -> dict:
    """Build structured report data with evidence."""
    risk = _risk_score(project, findings)
    coverage = _coverage_pct(project)
    severity_counts = {}
    for f in findings:
        s = f.get("severity", "info").lower()
        severity_counts[s] = severity_counts.get(s, 0) + 1
    owasp_map = {}
    cwe_map = {}
    for f in findings:
        o = f.get("owasp_category") or "Other"
        owasp_map[o] = owasp_map.get(o, 0) + 1
        c = f.get("cwe_id") or "N/A"
        cwe_map[c] = cwe_map.get(c, 0) + 1
    sorted_findings = sorted(findings, key=lambda x: _severity_order(x.get("severity", "")))
    for f in sorted_findings:
        f["compliance"] = get_compliance_mapping(cwe_id=f.get("cwe_id"), owasp_category=f.get("owasp_category"))
    return {
        "project": project,
        "findings": sorted_findings,
        "phases": phases,
        "project_id": project_id,
        "risk_score": risk,
        "risk_level": _risk_level(risk),
        "coverage_pct": coverage,
        "severity_distribution": severity_counts,
        "owasp_mapping": owasp_map,
        "cwe_mapping": cwe_map,
        "compliance_summary": {"OWASP Top 10": True, "CWE Top 25": True, "MITRE ATT&CK": True, "ISO 27001 Annex A": True, "NIST 800-53": True},
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def _html_escape(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_html(data: dict) -> str:
    """Generate Big 4 style professional HTML report with screenshots."""
    p = data["project"]
    findings = data["findings"]
    risk = data["risk_score"]
    risk_level = data.get("risk_level", "Medium")
    cov = data["coverage_pct"]
    sev = data["severity_distribution"]
    owasp = data["owasp_mapping"]
    cwe = data["cwe_mapping"]
    gen = data["generated_at"]
    project_id = data.get("project_id", "")

    sev_rows = "".join(
        f'<tr><td>{k.capitalize()}</td><td>{v}</td></tr>'
        for k, v in sorted(sev.items(), key=lambda x: _severity_order(x[0]))
    )
    owasp_rows = "".join(f'<tr><td>{_html_escape(k)}</td><td>{v}</td></tr>' for k, v in sorted(owasp.items()))
    cwe_rows = "".join(f'<tr><td>{_html_escape(k)}</td><td>{v}</td></tr>' for k, v in sorted(cwe.items()))

    find_rows = ""
    for i, f in enumerate(findings, 1):
        find_rows += f"""
        <tr>
            <td>{i}</td>
            <td>{_html_escape(f.get('title', ''))}</td>
            <td><span class="sev-{f.get('severity','').lower()}">{f.get('severity','')}</span></td>
            <td>{_html_escape(f.get('owasp_category') or '-')}</td>
            <td>{_html_escape(f.get('cwe_id') or '-')}</td>
            <td>{_html_escape(f.get('affected_url') or '-')}</td>
        </tr>
        """

    exec_bullets = []
    if findings:
        critical_high = sum(1 for x in findings if x.get("severity", "").lower() in ("critical", "high"))
        if critical_high:
            exec_bullets.append(f"<li><strong>{critical_high} Critical/High severity finding(s)</strong> require immediate remediation.</li>")
        exec_bullets.append(f"<li>Test coverage: <strong>{cov}%</strong> ({p.get('tested_count',0)} of {p.get('total_test_cases',0)} test cases executed).</li>")
        exec_bullets.append(f"<li>Findings mapped to OWASP Top 10, CWE Top 25, MITRE ATT&amp;CK, ISO 27001, and NIST 800-53.</li>")
        exec_bullets.append("<li>Recommendations provided for each finding to support remediation planning.</li>")
    else:
        exec_bullets.append("<li>No security findings identified during this assessment.</li>")
        exec_bullets.append(f"<li>Test coverage: <strong>{cov}%</strong>.</li>")
    exec_bullets_html = "".join(exec_bullets)

    scope = _html_escape(p.get("testing_scope") or "In-scope: Application under test. Out-of-scope: Third-party systems.")
    methodology = "Black-box" if p.get("testing_type") == "black_box" else "Grey-box" if p.get("testing_type") == "grey_box" else "White-box"
    methodology += f" testing in {p.get('environment', 'staging')} environment. Manual and semi-automated techniques per OWASP Testing Guide."

    sev_labels = list(sev.keys())
    sev_values = list(sev.values())
    sev_colors = ["#dc2626", "#ea580c", "#ca8a04", "#16a34a", "#2563eb"]
    toc_items = [
        ("1. Executive Summary", "exec-summary"),
        ("2. Scope & Methodology", "scope"),
        ("3. Risk Rating Methodology", "methodology"),
        ("4. Charts & Analytics", "charts"),
        ("5. Summary Statistics", "stats"),
        ("6. OWASP Top 10 Mapping", "owasp"),
        ("7. CWE Mapping", "cwe"),
        ("8. Compliance Frameworks", "compliance"),
        ("9. Detailed Findings", "findings-table"),
        ("10. Finding Details with Evidence", "finding-details"),
    ]
    toc_html = "".join(f'<li><a href="#{tid}" class="toc-link">{_html_escape(txt)}</a></li>' for txt, tid in toc_items)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {_html_escape(p.get('application_name', ''))}</title>
    <style>
        @page {{ margin: 2cm; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; margin: 0; padding: 2rem; color: #1f2937; line-height: 1.6; max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #111827; border-bottom: 3px solid #1e40af; padding-bottom: 0.5rem; font-size: 1.75rem; margin-top: 0; }}
        h2 {{ color: #1e40af; margin-top: 2.5rem; font-size: 1.25rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.25rem; }}
        h3 {{ color: #374151; margin-top: 1.5rem; font-size: 1.1rem; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem 0.75rem; text-align: left; }}
        th {{ background: #1e40af; color: white; font-weight: 600; }}
        tr:nth-child(even) {{ background: #f9fafb; }}
        .exec-summary {{ background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); padding: 1.75rem; border-radius: 8px; margin: 1.5rem 0; border-left: 4px solid #1e40af; }}
        .risk-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 700; font-size: 1.1rem; }}
        .risk-critical {{ background: #dc2626; color: white; }}
        .risk-high {{ background: #ea580c; color: white; }}
        .risk-medium {{ background: #ca8a04; color: white; }}
        .risk-low {{ background: #16a34a; color: white; }}
        .sev-critical {{ color: #dc2626; font-weight: 600; }}
        .sev-high {{ color: #ea580c; font-weight: 600; }}
        .sev-medium {{ color: #ca8a04; font-weight: 600; }}
        .sev-low {{ color: #16a34a; }}
        .sev-info {{ color: #2563eb; }}
        .meta {{ color: #6b7280; font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; }}
        .finding-block {{ margin: 2rem 0; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa; }}
        .evidence-img {{ max-width: 100%; height: auto; border: 1px solid #e5e7eb; border-radius: 4px; margin: 0.5rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .doc-control {{ background: #f3f4f6; padding: 1rem; border-radius: 4px; font-size: 0.85rem; margin: 1rem 0; }}
        ul {{ margin: 0.5rem 0; padding-left: 1.5rem; }}
        .toc {{ background: #f8fafc; padding: 1.25rem; border-radius: 8px; margin: 1.5rem 0; border: 1px solid #e2e8f0; }}
        .toc-link {{ color: #1e40af; text-decoration: none; }}
        .toc-link:hover {{ text-decoration: underline; }}
        .chart-container {{ max-width: 400px; margin: 1rem 0; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body>
    <h1>Application Security Testing Report</h1>
    <p><strong>Application:</strong> {_html_escape(p.get('application_name', ''))} | <strong>Version:</strong> {_html_escape(p.get('application_version') or 'N/A')}</p>
    <p><strong>Target URL:</strong> {_html_escape(p.get('application_url', ''))}</p>
    <p><strong>Environment:</strong> {_html_escape(p.get('environment', ''))} | <strong>Testing Type:</strong> {_html_escape(p.get('testing_type', ''))}</p>
    <p><strong>Classification:</strong> {_html_escape(p.get('classification') or 'Confidential')}</p>

    <div class="doc-control">
        <strong>Document Control</strong><br>
        Report Version: 1.0 | Generated: {gen} | Prepared by: VAPT Navigator
    </div>

    <nav class="toc">
        <strong>Table of Contents</strong>
        <ol style="margin: 0.5rem 0 0 1rem; padding: 0;">{toc_html}</ol>
    </nav>

    <h2 id="exec-summary">1. Executive Summary</h2>
    <div class="exec-summary">
        <p>This report presents the findings of a security assessment conducted on <strong>{_html_escape(p.get('application_name', ''))}</strong>. 
        The assessment evaluated the application against industry-standard security controls including OWASP Top 10, CWE Top 25, and related frameworks.</p>
        <p><strong>Overall Risk Rating:</strong> <span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span> ({risk}/100)</p>
        <p><strong>Key Points:</strong></p>
        <ul>{exec_bullets_html}</ul>
        <p><strong>Recommendation:</strong> Address Critical and High severity findings within 30 days. Medium and Low findings should be remediated in subsequent release cycles.</p>
    </div>

    <h2 id="scope">2. Scope & Methodology</h2>
    <p><strong>Scope:</strong> {scope}</p>
    <p><strong>Methodology:</strong> {methodology}</p>
    <p><strong>Target Completion:</strong> {_html_escape(p.get('target_completion_date') or 'N/A')}</p>

    <h2 id="methodology">3. Risk Rating Methodology</h2>
    <p>Findings are rated Critical, High, Medium, Low, or Informational based on CVSS considerations, exploitability, and business impact. 
    The overall risk score aggregates severity-weighted findings.</p>

    <h2 id="charts">4. Charts & Analytics</h2>
    <div style="display: flex; flex-wrap: wrap; gap: 2rem; margin: 1.5rem 0;">
        <div class="chart-container">
            <canvas id="severityChart" width="300" height="200"></canvas>
        </div>
        <div class="chart-container">
            <canvas id="owaspChart" width="350" height="200"></canvas>
        </div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {{
        var sevData = {json.dumps([{"label": k.capitalize(), "value": v, "color": sev_colors[i % len(sev_colors)]} for i, (k, v) in enumerate(sorted(sev.items(), key=lambda x: _severity_order(x[0])))])};
        if (sevData.length) {{
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{ labels: sevData.map(d => d.label), datasets: [{{ data: sevData.map(d => d.value), backgroundColor: sevData.map(d => d.color) }}] }},
                options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
            }});
        }}
        var owaspData = {json.dumps([{"label": k[:25] if len(k) > 25 else k, "value": v} for k, v in list(owasp.items())[:8]])};
        if (owaspData.length) {{
            new Chart(document.getElementById('owaspChart'), {{
                type: 'bar',
                data: {{ labels: owaspData.map(d => d.label), datasets: [{{ label: 'Count', data: owaspData.map(d => d.value), backgroundColor: '#1e40af' }}] }},
                options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }} }}
            }});
        }}
    }});
    </script>

    <h2 id="stats">5. Summary Statistics</h2>
    <table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>

    <h2 id="owasp">6. OWASP Top 10 Mapping</h2>
    <table><tr><th>Category</th><th>Count</th></tr>{owasp_rows}</table>

    <h2 id="cwe">7. CWE Mapping</h2>
    <table><tr><th>CWE ID</th><th>Count</th></tr>{cwe_rows}</table>

    <h2 id="compliance">8. Compliance Frameworks</h2>
    <p>Findings are mapped to: OWASP Top 10, CWE Top 25, MITRE ATT&amp;CK, ISO 27001 Annex A, NIST 800-53.</p>

    <h2 id="findings-table">9. Detailed Findings</h2>
    <table>
        <tr><th>#</th><th>Title</th><th>Severity</th><th>OWASP</th><th>CWE</th><th>Affected URL</th></tr>
        {find_rows}
    </table>

    <h2 id="finding-details">10. Finding Details with Evidence</h2>
"""
    for i, f in enumerate(findings, 1):
        comp = f.get("compliance") or {}
        comp_parts = []
        if comp.get("mitre_attack"):
            comp_parts.append(f"MITRE ATT&CK: {comp['mitre_attack']}")
        if comp.get("iso_27001"):
            comp_parts.append(f"ISO 27001: {comp['iso_27001']}")
        if comp.get("nist_800_53"):
            comp_parts.append(f"NIST 800-53: {comp['nist_800_53']}")
        comp_str = " | ".join(comp_parts) if comp_parts else ""

        evidence_html = ""
        evidence_list = f.get("evidence") or []
        for ev in evidence_list:
            if isinstance(ev, dict):
                b64 = _evidence_to_base64(project_id, ev)
                if b64:
                    fn = ev.get("filename", "Evidence")
                    evidence_html += f'<p><strong>Evidence: {_html_escape(fn)}</strong></p><img src="{b64}" alt="{_html_escape(fn)}" class="evidence-img" style="max-width: 600px;" />'

        html += f"""
    <div class="finding-block">
        <h3>Finding #{i}: {_html_escape(f.get('title',''))} <span class="sev-{f.get('severity','').lower()}">[{f.get('severity','')}]</span></h3>
        <p><strong>Description:</strong><br>{_html_escape(f.get('description') or '-').replace(chr(10), '<br>')}</p>
        <p><strong>Affected URL:</strong> {_html_escape(f.get('affected_url') or '-')}</p>
        <p><strong>CVSS Score:</strong> {_html_escape(f.get('cvss_score') or 'N/A')}</p>
        <p><strong>Impact:</strong><br>{_html_escape(f.get('impact') or '-').replace(chr(10), '<br>')}</p>
        <p><strong>Reproduction Steps:</strong><br>{_html_escape(f.get('reproduction_steps') or '-').replace(chr(10), '<br>')}</p>
        {evidence_html}
        <p><strong>Recommendation:</strong><br>{_html_escape(f.get('recommendation') or '-').replace(chr(10), '<br>')}</p>
        {f'<p><strong>Compliance Mapping:</strong> {_html_escape(comp_str)}</p>' if comp_str else ''}
    </div>
"""
    html += f"""
    <p class="meta">Report generated by VAPT Navigator at {gen}. This document is confidential and intended for authorized recipients only.</p>
</body>
</html>
"""
    return html


def generate_docx(data: dict) -> bytes:
    """Generate Big 4 style professional DOCX report with embedded screenshots."""
    doc = Document()
    p = data["project"]
    findings = data["findings"]
    risk = data["risk_score"]
    risk_level = data.get("risk_level", "Medium")
    cov = data["coverage_pct"]
    project_id = data.get("project_id", "")

    doc.add_heading("Vulnerability Assessment & Penetration Testing Report", 0)
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph(f"Application: {p.get('application_name', '')}")
    doc.add_paragraph(f"Target URL: {p.get('application_url', '')}")
    doc.add_paragraph(f"Environment: {p.get('environment', '')} | Testing Type: {p.get('testing_type', '')}")
    doc.add_paragraph(f"Classification: {p.get('classification') or 'Confidential'}")
    doc.add_paragraph(f"Report Generated: {data['generated_at']}")
    doc.add_paragraph()

    doc.add_heading("1. Executive Summary", level=1)
    doc.add_paragraph(
        f"This report presents the findings of a security assessment conducted on {p.get('application_name', '')}. "
        "The assessment evaluated the application against industry-standard security controls including OWASP Top 10 and CWE Top 25."
    )
    doc.add_paragraph(f"Overall Risk Rating: {risk_level} ({risk}/100)")
    doc.add_paragraph(f"Test Coverage: {cov}% ({p.get('tested_count',0)}/{p.get('total_test_cases',0)} test cases)")
    doc.add_paragraph(f"Total Findings: {len(findings)}")
    doc.add_paragraph()
    doc.add_paragraph(
        "Recommendation: Address Critical and High severity findings within 30 days. "
        "Medium and Low findings should be remediated in subsequent release cycles."
    )
    doc.add_paragraph()

    doc.add_heading("2. Scope & Methodology", level=1)
    doc.add_paragraph(f"Scope: {p.get('testing_scope') or 'In-scope: Application under test.'}")
    methodology = "Black-box" if p.get("testing_type") == "black_box" else "Grey-box" if p.get("testing_type") == "grey_box" else "White-box"
    doc.add_paragraph(f"Methodology: {methodology} testing in {p.get('environment', 'staging')} environment.")
    doc.add_paragraph()

    doc.add_heading("3. Severity Distribution", level=1)
    table = doc.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "Count"
    for k, v in sorted(data["severity_distribution"].items(), key=lambda x: _severity_order(x[0])):
        row = table.add_row().cells
        row[0].text = k.capitalize()
        row[1].text = str(v)
    doc.add_paragraph()

    doc.add_heading("4. OWASP Top 10 Mapping", level=1)
    table2 = doc.add_table(rows=1, cols=2)
    table2.style = "Table Grid"
    h2 = table2.rows[0].cells
    h2[0].text = "Category"
    h2[1].text = "Count"
    for k, v in data["owasp_mapping"].items():
        row = table2.add_row().cells
        row[0].text = str(k)
        row[1].text = str(v)
    doc.add_paragraph()

    doc.add_heading("5. Detailed Findings with Evidence", level=1)
    for i, f in enumerate(findings, 1):
        doc.add_heading(f"Finding #{i}: {f.get('title','')} [{f.get('severity','')}]", level=2)
        doc.add_paragraph(f"Description: {f.get('description') or '-'}")
        doc.add_paragraph(f"Affected URL: {f.get('affected_url') or '-'}")
        doc.add_paragraph(f"CVSS Score: {f.get('cvss_score') or 'N/A'}")
        doc.add_paragraph(f"Impact: {f.get('impact') or '-'}")
        doc.add_paragraph(f"Reproduction Steps: {f.get('reproduction_steps') or '-'}")

        evidence_list = f.get("evidence") or []
        for ev in evidence_list:
            if isinstance(ev, dict):
                fpath = _get_evidence_file_path(project_id, ev)
                if fpath and fpath.exists() and fpath.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                    try:
                        doc.add_paragraph(f"Evidence: {ev.get('filename', 'Screenshot')}")
                        doc.add_picture(str(fpath), width=Inches(5.5))
                        doc.add_paragraph()
                    except Exception:
                        pass

        doc.add_paragraph(f"Recommendation: {f.get('recommendation') or '-'}")
        doc.add_paragraph()

    doc.add_paragraph(f"Report generated by VAPT Navigator at {data['generated_at']}")
    doc.add_paragraph("This document is confidential and intended for authorized recipients only.")

    buf = BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.getvalue()


def generate_pdf(data: dict) -> bytes:
    """Generate Big 4 style professional PDF report with embedded screenshots."""
    if not FPDF:
        raise RuntimeError("fpdf2 not installed")
    p = data["project"]
    findings = data["findings"]
    risk = data["risk_score"]
    risk_level = data.get("risk_level", "Medium")
    cov = data["coverage_pct"]
    sev = data["severity_distribution"]
    project_id = data.get("project_id", "")

    def safe_text(s, max_len: int = 250) -> str:
        t = str(s or "-").replace("\n", " ").replace("\r", "")[:max_len]
        return t if t else "-"

    class ReportPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 11)
            self.cell(0, 8, "VAPT Security Assessment Report", ln=True, align="C")
            self.set_font("Helvetica", "", 9)
            self.cell(0, 5, f"{p.get('application_name', '')} | {p.get('application_url', '')}", ln=True, align="C")
            self.ln(3)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.cell(0, 10, f"Page {self.page_no()} | Confidential", ln=True, align="C")

    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(190, 5, f"This report presents the findings of a security assessment on {p.get('application_name', '')}. "
        "The assessment evaluated the application against OWASP Top 10, CWE Top 25, and related frameworks.")
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(60, 6, "Overall Risk Rating:", ln=0)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"{risk_level} ({risk}/100)", ln=True)
    pdf.cell(60, 6, "Test Coverage:", ln=0)
    pdf.cell(0, 6, f"{cov}% ({p.get('tested_count',0)}/{p.get('total_test_cases',0)} test cases)", ln=True)
    pdf.cell(60, 6, "Total Findings:", ln=0)
    pdf.cell(0, 6, str(len(findings)), ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "2. Severity Distribution", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for k, v in sorted(sev.items(), key=lambda x: _severity_order(x[0])):
        pdf.cell(0, 6, f"  {k.capitalize()}: {v}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "3. Detailed Findings with Evidence", ln=True)
    pdf.set_font("Helvetica", "", 9)
    w = 190
    for i, f in enumerate(findings, 1):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(w, 6, f"Finding #{i}: {safe_text(f.get('title',''), 70)} [{f.get('severity','')}]")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(w, 5, f"Description: {safe_text(f.get('description'), 300)}")
        pdf.multi_cell(w, 5, f"Affected URL: {safe_text(f.get('affected_url'), 120)}")
        pdf.multi_cell(w, 5, f"Impact: {safe_text(f.get('impact'), 200)}")
        pdf.multi_cell(w, 5, f"Reproduction: {safe_text(f.get('reproduction_steps'), 200)}")

        evidence_list = f.get("evidence") or []
        for ev in evidence_list:
            if isinstance(ev, dict):
                fpath = _get_evidence_file_path(project_id, ev)
                if fpath and fpath.exists() and fpath.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                    try:
                        pdf.ln(2)
                        pdf.set_font("Helvetica", "I", 8)
                        pdf.cell(0, 5, f"Evidence: {ev.get('filename', 'Screenshot')}", ln=True)
                        pdf.image(str(fpath), x=10, w=180)
                        pdf.ln(2)
                        pdf.set_font("Helvetica", "", 9)
                    except Exception:
                        pass

        pdf.multi_cell(w, 5, f"Recommendation: {safe_text(f.get('recommendation'), 250)}")
        pdf.ln(3)

    buf = BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return buf.getvalue()


def generate_json(data: dict) -> str:
    import json
    out = dict(data)
    for f in out.get("findings", []):
        f.pop("compliance", None)
    return json.dumps(out, indent=2)


def generate_csv(data: dict) -> str:
    import csv
    from io import StringIO
    findings = data["findings"]
    if not findings:
        return "title,severity,owasp_category,cwe_id,affected_url,description,impact,recommendation\n"
    out = StringIO()
    keys = ["title", "severity", "owasp_category", "cwe_id", "affected_url", "description", "impact", "recommendation"]
    w = csv.DictWriter(out, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    for f in findings:
        w.writerow({k: (f.get(k) or "") for k in keys})
    return out.getvalue()
