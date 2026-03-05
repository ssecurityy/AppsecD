from pydantic import BaseModel, Field, field_validator
from typing import Optional
import uuid

# Reject null bytes and RTL override (U+202E) in string fields
def _reject_control_and_rtl(v: str) -> str:
    if v is None:
        return v
    if "\x00" in v or "\u202e" in v or "\u202d" in v:
        raise ValueError("Invalid characters in field")
    return v


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    application_name: str = Field(..., min_length=1, max_length=255)
    application_version: Optional[str] = None
    application_url: str
    app_owner_name: Optional[str] = None
    app_spoc_name: Optional[str] = None
    app_spoc_email: Optional[str] = None
    testing_type: str = "grey_box"
    environment: str = "staging"
    testing_scope: Optional[str] = None
    target_completion_date: Optional[str] = None  # ISO date string
    classification: Optional[str] = None  # internal, confidential, public
    lead_id: Optional[uuid.UUID] = None
    assigned_tester_ids: Optional[list[uuid.UUID]] = None
    stack_profile: dict = {}

    @field_validator("name", "application_name")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        return _reject_control_and_rtl(v)


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    application_name: str
    application_version: Optional[str]
    application_url: str
    app_owner_name: Optional[str]
    app_spoc_name: Optional[str]
    app_spoc_email: Optional[str]
    status: str
    testing_type: str
    environment: str
    stack_profile: dict
    total_test_cases: int
    tested_count: int
    passed_count: int
    failed_count: int
    na_count: int
    risk_rating: str
    created_at: str

    class Config:
        from_attributes = True


class ProjectUpdate(BaseModel):
    status: Optional[str] = None
    stack_profile: Optional[dict] = None
    risk_rating: Optional[str] = None


class ProjectMemberCreate(BaseModel):
    user_id: uuid.UUID
    role: str  # viewer, tester, manager
    can_read: Optional[bool] = None
    can_write: Optional[bool] = None
    can_download_report: Optional[bool] = None
    can_manage_members: Optional[bool] = None


class ProjectMemberUpdate(BaseModel):
    role: Optional[str] = None
    can_read: Optional[bool] = None
    can_write: Optional[bool] = None
    can_download_report: Optional[bool] = None
    can_manage_members: Optional[bool] = None


class ProjectMemberOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    can_read: bool
    can_write: bool
    can_download_report: bool
    can_manage_members: bool

    class Config:
        from_attributes = True
