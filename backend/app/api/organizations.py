"""Organizations API — multi-tenant org management with branding support."""
import uuid as _uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.config import get_settings
from app.api.auth import get_current_user, require_admin, require_super_admin, get_client_ip
from app.models.user import User
from app.models.organization import Organization
from app.models.project import Project
from app.services.audit_service import log_audit
from pydantic import BaseModel
import re
import aiofiles

router = APIRouter(prefix="/organizations", tags=["organizations"])

settings = get_settings()

LOGO_UPLOAD_DIR = Path("/opt/navigator/data/uploads/org_logos")
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
MAX_LOGO_SIZE = 5 * 1024 * 1024  # 5MB


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _org_to_dict(o: Organization) -> dict:
    """Serialize organization with branding fields."""
    return {
        "id": str(o.id),
        "name": o.name,
        "slug": o.slug,
        "is_active": o.is_active,
        "logo_url": o.logo_url,
        "brand_color": o.brand_color,
        "description": o.description,
    }


class OrgCreate(BaseModel):
    name: str
    slug: str | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    brand_color: str | None = None


class OrgOut(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool
    logo_url: str | None = None
    brand_color: str | None = None
    description: str | None = None


@router.post("", response_model=dict)
async def create_organization(
    request: Request,
    payload: OrgCreate,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization (super_admin only)."""
    slug = payload.slug or slugify(payload.name)
    if not slug:
        raise HTTPException(400, "Invalid name or slug")
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(409, f"Organization with slug '{slug}' already exists")
    org = Organization(name=payload.name, slug=slug)
    db.add(org)
    await db.flush()
    await log_audit(db, "create_organization", user_id=str(current_user.id), resource_type="organization", resource_id=str(org.id), details={"name": org.name, "slug": slug}, ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(org)
    return _org_to_dict(org)


@router.get("/my-branding", response_model=dict)
async def get_my_branding(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current user's organization branding (logo_url, brand_color, name) for Navbar."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {"name": None, "logo_url": None, "brand_color": None, "description": None}
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        return {"name": None, "logo_url": None, "brand_color": None, "description": None}
    return {
        "name": org.name,
        "logo_url": org.logo_url,
        "brand_color": org.brand_color,
        "description": org.description,
    }


@router.get("", response_model=list)
async def list_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List organizations. Super_admin sees all; admin sees only their org; others see only their org."""
    if current_user.role == "super_admin":
        result = await db.execute(select(Organization).where(Organization.is_active == True))
        orgs = result.scalars().all()
    elif current_user.role == "admin":
        if not getattr(current_user, "organization_id", None):
            return []
        result = await db.execute(
            select(Organization).where(
                Organization.id == current_user.organization_id,
                Organization.is_active == True,
            )
        )
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
    return [_org_to_dict(o) for o in orgs]


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
    if current_user.role not in ("admin", "super_admin") and getattr(current_user, "organization_id") != org.id:
        raise HTTPException(403, "Access denied")
    return _org_to_dict(org)


@router.patch("/{org_id}", response_model=dict)
async def update_organization(
    request: Request,
    org_id: str,
    payload: OrgUpdate,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update organization details including branding (super_admin only)."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    if payload.name is not None:
        org.name = payload.name
    if payload.description is not None:
        org.description = payload.description
    if payload.brand_color is not None:
        # Validate hex color format
        color = payload.brand_color.strip()
        if color and not re.match(r'^#[0-9a-fA-F]{3,8}$', color):
            raise HTTPException(400, "Invalid brand_color format. Use hex color (e.g., #FF5733)")
        org.brand_color = color or None
    await log_audit(db, "update_organization", user_id=str(current_user.id), resource_type="organization", resource_id=str(org.id), details={"fields_updated": [k for k, v in payload.model_dump().items() if v is not None]}, ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(org)
    return _org_to_dict(org)


@router.post("/{org_id}/logo", response_model=dict)
async def upload_org_logo(
    org_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Upload a logo image for an organization (super_admin only)."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    ext = Path(file.filename or "logo.png").suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(400, f"File type not allowed. Allowed: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}")

    content = await file.read()
    if len(content) > MAX_LOGO_SIZE:
        raise HTTPException(400, f"File too large. Max {MAX_LOGO_SIZE // 1024 // 1024}MB")
    if len(content) == 0:
        raise HTTPException(400, "Empty file not allowed")

    # Ensure upload directory exists
    LOGO_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # Save as {org_id}{ext} (e.g., {org_id}.png)
    safe_name = f"{org_id}{ext}"
    upload_path = LOGO_UPLOAD_DIR / safe_name

    async with aiofiles.open(upload_path, "wb") as f:
        await f.write(content)

    # Store the URL path in the org record
    logo_url = f"/organizations/{org_id}/logo"
    org.logo_url = logo_url
    await db.commit()
    await db.refresh(org)

    return {"logo_url": logo_url, "filename": file.filename or f"logo{ext}"}


@router.get("/{org_id}/logo")
async def get_org_logo(
    org_id: str,
):
    """Serve the organization logo file. Public endpoint — logos are not sensitive."""
    # Find any logo file for this org
    if not LOGO_UPLOAD_DIR.exists():
        raise HTTPException(404, "Logo not found")

    logo_file = None
    for ext in ALLOWED_IMAGE_EXTENSIONS:
        candidate = LOGO_UPLOAD_DIR / f"{org_id}{ext}"
        if candidate.exists():
            logo_file = candidate
            break

    if not logo_file:
        raise HTTPException(404, "Logo not found")

    media_types = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp",
    }
    ext = logo_file.suffix.lower()
    media_type = media_types.get(ext, "image/png")
    return FileResponse(logo_file, media_type=media_type, filename=f"logo{ext}")


@router.patch("/{org_id}/assign-user")
async def assign_user_to_org(
    org_id: str,
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Assign a user to an organization. Super_admin: any org. Admin: only their org."""
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    if current_user.role == "admin" and current_user.organization_id != org.id:
        raise HTTPException(403, "Admin can only assign users to their organization")
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
    """Assign a project to an organization. Admin: only their org."""
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    if current_user.role == "admin" and current_user.organization_id != org.id:
        raise HTTPException(403, "Admin can only assign projects to their organization")
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    project.organization_id = org.id
    await db.commit()
    return {"ok": True}
