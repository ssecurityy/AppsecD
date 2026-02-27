"""Organizations API — multi-tenant org management."""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.api.auth import get_current_user, require_admin
from app.models.user import User
from app.models.organization import Organization
from app.models.project import Project
from pydantic import BaseModel
import re

router = APIRouter(prefix="/organizations", tags=["organizations"])


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


class OrgCreate(BaseModel):
    name: str
    slug: str | None = None


class OrgOut(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool


@router.post("", response_model=dict)
async def create_organization(
    payload: OrgCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization (admin only)."""
    slug = payload.slug or slugify(payload.name)
    if not slug:
        raise HTTPException(400, "Invalid name or slug")
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(409, f"Organization with slug '{slug}' already exists")
    org = Organization(name=payload.name, slug=slug)
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return {"id": str(org.id), "name": org.name, "slug": org.slug}


@router.get("", response_model=list)
async def list_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all organizations (admin sees all; others see only their org)."""
    if current_user.role == "admin":
        result = await db.execute(select(Organization).where(Organization.is_active == True))
        orgs = result.scalars().all()
    else:
        if not getattr(current_user, "organization_id", None):
            return []
        result = await db.execute(
            select(Organization).where(
                Organization.id == current_user.organization_id,
                Organization.is_active == True,
            )
        )
        orgs = result.scalars().all()
    return [{"id": str(o.id), "name": o.name, "slug": o.slug} for o in orgs]


@router.get("/{org_id}", response_model=dict)
async def get_organization(
    org_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization by ID."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    if current_user.role != "admin" and getattr(current_user, "organization_id") != org.id:
        raise HTTPException(403, "Access denied")
    return {"id": str(org.id), "name": org.name, "slug": org.slug}


@router.patch("/{org_id}/assign-user")
async def assign_user_to_org(
    org_id: str,
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Assign a user to an organization (admin only)."""
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.organization_id = org.id
    await db.commit()
    return {"ok": True}


@router.patch("/{org_id}/assign-project")
async def assign_project_to_org(
    org_id: str,
    project_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Assign a project to an organization (admin only)."""
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    project.organization_id = org.id
    await db.commit()
    return {"ok": True}
