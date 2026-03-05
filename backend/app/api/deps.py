"""Shared dependencies for API (e.g. path param validation)."""
import uuid
from fastapi import HTTPException, Path


def validate_project_id(project_id: str = Path(..., description="Project UUID")) -> uuid.UUID:
    """Validate project_id path param; return UUID or raise 400."""
    try:
        return uuid.UUID(project_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, "Invalid project ID")
