"""Audit logs API — admin+ access. Platform-level audit trail with advanced filtering."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from datetime import datetime, date
from app.core.database import get_db
from app.api.auth import require_super_admin, require_admin, get_current_user
from app.models.audit_log import AuditLog
from app.models.user import User

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit_logs(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    action: str = Query(None, description="Filter by action type"),
    resource_type: str = Query(None, description="Filter by resource type"),
    org_id: str | None = Query(None, description="Filter by org (super_admin only)"),
    user_id: str | None = Query(None, description="Filter by user ID"),
    search: str | None = Query(None, description="Search in action/resource"),
    date_from: str | None = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: str | None = Query(None, description="End date (YYYY-MM-DD)"),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List audit logs. Admin sees own org, super_admin sees all."""
    conditions = []

    # Org admin: scope to their own organization's users only
    if current_user.role == "admin":
        org_user_ids = select(User.id).where(User.organization_id == current_user.organization_id)
        conditions.append(AuditLog.user_id.in_(org_user_ids))
    elif org_id:
        # Super admin can filter by any org
        from uuid import UUID
        try:
            oid = UUID(org_id)
            org_user_ids = select(User.id).where(User.organization_id == oid)
            conditions.append(AuditLog.user_id.in_(org_user_ids))
        except ValueError:
            pass

    if action:
        conditions.append(AuditLog.action == action)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if search:
        conditions.append(
            AuditLog.action.ilike(f"%{search}%") | AuditLog.resource_type.ilike(f"%{search}%")
        )
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, "%Y-%m-%d")
            conditions.append(AuditLog.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            conditions.append(AuditLog.created_at <= dt_to)
        except ValueError:
            pass

    # Get total count
    count_query = select(func.count(AuditLog.id))
    if conditions:
        count_query = count_query.where(and_(*conditions))
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get logs with user info
    query = (
        select(AuditLog, User)
        .outerjoin(User, AuditLog.user_id == User.id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
        .offset(offset)
    )
    if conditions:
        query = query.where(and_(*conditions))

    result = await db.execute(query)
    rows = result.all()

    logs = []
    for log_entry, user in rows:
        logs.append({
            "id": str(log_entry.id),
            "user_id": str(log_entry.user_id) if log_entry.user_id else None,
            "user_name": user.full_name if user else "System",
            "user_email": user.email if user else None,
            "user_role": user.role if user else None,
            "action": log_entry.action,
            "resource_type": log_entry.resource_type,
            "resource_id": log_entry.resource_id,
            "details": log_entry.details or {},
            "ip_address": log_entry.ip_address,
            "user_agent": log_entry.user_agent,
            "created_at": log_entry.created_at.isoformat() if log_entry.created_at else None,
        })

    # Get distinct actions and resource types for filter dropdowns (super_admin sees all)
    base_conditions = []

    actions_q = select(AuditLog.action).distinct()
    if base_conditions:
        actions_q = actions_q.where(and_(*base_conditions))
    actions_result = await db.execute(actions_q)
    actions = sorted([r[0] for r in actions_result.all() if r[0]])

    res_types_q = select(AuditLog.resource_type).distinct().where(AuditLog.resource_type.isnot(None))
    if base_conditions:
        res_types_q = res_types_q.where(and_(*base_conditions))
    res_types_result = await db.execute(res_types_q)
    resource_types = sorted([r[0] for r in res_types_result.all() if r[0]])

    return {
        "logs": logs,
        "total": total,
        "actions": actions,
        "resource_types": resource_types,
    }


@router.get("/stats")
async def audit_stats(
    days: int = Query(30, le=365),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get audit statistics. Admin sees own org, super_admin sees all."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)

    conditions = [AuditLog.created_at >= cutoff]

    # Org admin: scope to own org
    if current_user.role == "admin":
        org_user_ids = select(User.id).where(User.organization_id == current_user.organization_id)
        conditions.append(AuditLog.user_id.in_(org_user_ids))

    # Total events
    total_q = select(func.count(AuditLog.id)).where(and_(*conditions))
    total = (await db.execute(total_q)).scalar() or 0

    # By action
    action_q = (
        select(AuditLog.action, func.count(AuditLog.id))
        .where(and_(*conditions))
        .group_by(AuditLog.action)
        .order_by(desc(func.count(AuditLog.id)))
        .limit(10)
    )
    action_result = await db.execute(action_q)
    by_action = [{"action": a, "count": c} for a, c in action_result.all()]

    # By day (last 7 days)
    daily_q = (
        select(
            func.date_trunc('day', AuditLog.created_at).label('day'),
            func.count(AuditLog.id)
        )
        .where(and_(*conditions))
        .group_by('day')
        .order_by('day')
    )
    daily_result = await db.execute(daily_q)
    by_day = [{"date": d.isoformat() if d else "", "count": c} for d, c in daily_result.all()]

    # Unique users
    unique_users_q = select(func.count(func.distinct(AuditLog.user_id))).where(and_(*conditions))
    unique_users = (await db.execute(unique_users_q)).scalar() or 0

    return {
        "total_events": total,
        "unique_users": unique_users,
        "by_action": by_action,
        "by_day": by_day,
    }
