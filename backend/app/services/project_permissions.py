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
    """Admin sees all; others only if they are project members."""
    if user.role == "admin":
        return True
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        )
    )
    return r.scalar_one_or_none() is not None


async def get_project_member(db: AsyncSession, user: User, project_id: str) -> ProjectMember | None:
    if user.role == "admin":
        return None  # admin bypasses project-level checks
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        )
    )
    return r.scalar_one_or_none()


async def user_can_read_project(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "admin":
        return True
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_read


async def user_can_write_project(db: AsyncSession, user: User, project_id: str) -> bool:
    """Write = mark status, add/edit findings."""
    if user.role == "admin":
        return True
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_read and pm.can_write


async def user_can_download_report(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "admin":
        return True
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_download_report


async def user_can_manage_members(db: AsyncSession, user: User, project_id: str) -> bool:
    if user.role == "admin":
        return True
    pm = await get_project_member(db, user, project_id)
    return pm is not None and pm.can_manage_members


async def get_visible_project_ids(db: AsyncSession, user: User) -> list | None:
    """Returns list of project UUIDs user can see, or None if admin (sees all)."""
    if user.role == "admin":
        return None
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
