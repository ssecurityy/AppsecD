"""Project-level permissions: visibility and per-action checks."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.models.project_member import ProjectMember
from app.models.project import Project
from app.models.user import User

PROJECT_ROLES = ("viewer", "tester", "manager")

# Role defaults: viewer=read+report, tester=read+write+report, manager=all
ROLE_DEFAULTS = {
    "viewer": {"can_read": True, "can_write": False, "can_download_report": True, "can_manage_members": False},
    "tester": {"can_read": True, "can_write": True, "can_download_report": True, "can_manage_members": False},
    "manager": {"can_read": True, "can_write": True, "can_download_report": True, "can_manage_members": True},
}


async def user_can_see_project(db: AsyncSession, user: User, project_id: str) -> bool:
    """Super_admin sees all; admin sees only their org's projects; others need project membership."""
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        return p is not None and p.organization_id == getattr(user, "organization_id", None)
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        )
    )
    return r.scalar_one_or_none() is not None


async def get_project_member(db: AsyncSession, user: User, project_id: str) -> ProjectMember | None:
    if user.role == "super_admin":
        return None  # super_admin bypasses project-level checks
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        if p and p.organization_id == getattr(user, "organization_id", None):
            return None  # admin bypasses for their org's projects
        return None  # will fail read check
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        )
    )
    return r.scalar_one_or_none()


async def user_can_read_project(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        return p is not None and p.organization_id == getattr(user, "organization_id", None)
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_read


async def user_can_write_project(db: AsyncSession, user: User, project_id: str) -> bool:
    """Write = mark status, add/edit findings."""
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        return p is not None and p.organization_id == getattr(user, "organization_id", None)
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_read and pm.can_write


async def user_can_download_report(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        return p is not None and p.organization_id == getattr(user, "organization_id", None)
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_download_report


async def user_can_manage_members(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "super_admin":
        return True
    if user.role == "admin":
        r = await db.execute(select(Project).where(Project.id == project_id))
        p = r.scalar_one_or_none()
        return p is not None and p.organization_id == getattr(user, "organization_id", None)
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_manage_members


async def get_visible_project_ids(db: AsyncSession, user: User) -> list | None:
    """Returns list of project UUIDs user can see, or None if super_admin (sees all)."""
    if user.role == "super_admin":
        return None
    if user.role == "admin":
        org_id = getattr(user, "organization_id", None)
        if not org_id:
            return []
        r = await db.execute(select(Project.id).where(Project.organization_id == org_id))
        return [row[0] for row in r.all()]
    r = await db.execute(
        select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)
    )
    ids = [row[0] for row in r.all()]
    # Multi-tenant: if user has org_id, only include projects in same org (or no org)
    org_id = getattr(user, "organization_id", None)
    if org_id and ids:
        r2 = await db.execute(
            select(Project.id).where(
                Project.id.in_(ids),
                or_(Project.organization_id == org_id, Project.organization_id.is_(None)),
            )
        )
        ids = [row[0] for row in r2.all()]
    return ids
