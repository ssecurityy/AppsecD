"""In-app notifications API (4E)."""
import uuid
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.notification import Notification
from app.models.user import User

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List notifications for current user (paginated, unread first)."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {"items": [], "total": 0, "page": page, "per_page": per_page}
    base = select(Notification).where(
        Notification.organization_id == org_id,
        (Notification.user_id.is_(None)) | (Notification.user_id == current_user.id),
    )
    total_q = await db.execute(select(func.count()).select_from(Notification).where(
        Notification.organization_id == org_id,
        (Notification.user_id.is_(None)) | (Notification.user_id == current_user.id),
    ))
    total = total_q.scalar() or 0
    q = (
        base.order_by(Notification.is_read.asc(), desc(Notification.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    rows = (await db.execute(q)).scalars().all()
    items = [
        {
            "id": str(n.id),
            "type": n.type,
            "title": n.title,
            "message": n.message,
            "severity": n.severity,
            "resource_type": n.resource_type,
            "resource_id": str(n.resource_id) if n.resource_id else None,
            "is_read": n.is_read,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in rows
    ]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


@router.get("/unread-count")
async def unread_count(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return unread notification count for current user."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {"count": 0}
    q = select(func.count()).select_from(Notification).where(
        Notification.organization_id == org_id,
        (Notification.user_id.is_(None)) | (Notification.user_id == current_user.id),
        Notification.is_read == False,
    )
    result = await db.execute(q)
    return {"count": result.scalar() or 0}


@router.patch("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a notification as read."""
    n = (await db.execute(
        select(Notification).where(Notification.id == uuid.UUID(notification_id))
    )).scalar_one_or_none()
    if not n:
        raise HTTPException(404, "Notification not found")
    org_id = getattr(current_user, "organization_id", None)
    if str(n.organization_id) != str(org_id):
        raise HTTPException(403, "Access denied")
    n.is_read = True
    await db.commit()
    return {"ok": True}


@router.patch("/mark-all-read")
async def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark all notifications as read for current user."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {"ok": True}
    from sqlalchemy import update
    await db.execute(
        update(Notification).where(
            Notification.organization_id == org_id,
            (Notification.user_id.is_(None)) | (Notification.user_id == current_user.id),
            Notification.is_read == False,
        ).values(is_read=True)
    )
    await db.commit()
    return {"ok": True}


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a notification."""
    n = (await db.execute(
        select(Notification).where(Notification.id == uuid.UUID(notification_id))
    )).scalar_one_or_none()
    if not n:
        raise HTTPException(404, "Notification not found")
    org_id = getattr(current_user, "organization_id", None)
    if str(n.organization_id) != str(org_id):
        raise HTTPException(403, "Access denied")
    await db.delete(n)
    await db.commit()
    return {"ok": True}
