from pydantic import BaseModel
from typing import Optional
import uuid


class ResultUpdate(BaseModel):
    status: Optional[str] = None  # not_started, in_progress, passed, failed, na, blocked
    notes: Optional[str] = None
    evidence: Optional[list] = None
    request_captured: Optional[str] = None
    response_captured: Optional[str] = None
    reproduction_steps: Optional[str] = None
    tool_used: Optional[str] = None
    payload_used: Optional[str] = None
    time_spent_seconds: Optional[int] = None
    severity_override: Optional[str] = None
    is_applicable: Optional[bool] = None


class ResultOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    test_case_id: uuid.UUID
    status: str
    is_applicable: bool
    notes: Optional[str]
    evidence: list
    tool_used: Optional[str]
    payload_used: Optional[str]

    class Config:
        from_attributes = True


class FindingCreate(BaseModel):
    project_id: uuid.UUID
    test_result_id: Optional[uuid.UUID] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    reproduction_steps: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None


class FindingOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    title: str
    severity: str
    status: str
    owasp_category: Optional[str]
    affected_url: Optional[str]
    created_at: str

    class Config:
        from_attributes = True
