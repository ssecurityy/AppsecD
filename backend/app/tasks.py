"""Celery tasks for async report generation."""
from app.celery_app import celery_app
from app.services.report_service import generate_docx, generate_pdf
import json


@celery_app.task
def generate_report_async(project_id: str, format: str, report_data_json: str):
    """
    Generate report in background. report_data_json is the output of build_report_data.
    Returns dict with format and hex-encoded bytes for JSON serialization.
    """
    data = json.loads(report_data_json)
    if format == "docx":
        content = generate_docx(data)
        return {"format": "docx", "content_hex": content.hex()}
    if format == "pdf":
        content = generate_pdf(data)
        return {"format": "pdf", "content_hex": content.hex()}
    return None
