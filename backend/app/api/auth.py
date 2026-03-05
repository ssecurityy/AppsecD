"""Authentication API."""
import uuid
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.core.database import get_db
from app.services.audit_service import log_audit
from app.core.security import hash_password, verify_password, create_access_token, create_mfa_pending_token, decode_token
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate, UserPasswordUpdate, UserLogin, UserOut, UserAdminOut, TokenOut

from app.core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Admin or super_admin — org-scoped for admin, platform for super_admin."""
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(403, "Admin access required")
    return current_user


def require_super_admin(current_user: User = Depends(get_current_user)) -> User:
    """Super admin only — platform owner, can create orgs and admins."""
    if current_user.role != "super_admin":
        raise HTTPException(403, "Super admin access required")
    return current_user


@router.post("/register")
async def register():
    """Registration disabled for security. Use admin to create accounts."""
    raise HTTPException(403, "Self-registration is disabled. Contact your administrator.")


@router.post("/login", response_model=TokenOut)
@limiter.limit("5/minute")
async def login(request: Request, payload: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    from datetime import datetime, date
    today = date.today()
    user.last_login = datetime.utcnow()
    client_ip = request.headers.get("x-forwarded-for") or request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)
    await log_audit(db, "login", user_id=str(user.id), ip_address=client_ip, user_agent=request.headers.get("user-agent"))
    # Update streak
    last = user.last_streak_date
    if last is None:
        user.streak_days = 1
        user.last_streak_date = today
    elif last == today:
        pass  # Same day, no change
    elif (today - last).days == 1:
        new_streak = (user.streak_days or 0) + 1
        user.streak_days = new_streak
        user.last_streak_date = today
        if new_streak == 5:  # 5-day streak bonus
            user.xp_points = (user.xp_points or 0) + 150
            user.level = max(1, (user.xp_points // 500) + 1)
    else:
        user.streak_days = 1
        user.last_streak_date = today
    await db.commit()
    await db.refresh(user)

    # MFA enforcement for all users who have MFA enabled
    if getattr(user, "mfa_enabled", False):
        mfa_token = create_mfa_pending_token(str(user.id))
        # If user has no secret yet, they need to set up MFA first (scan QR code)
        if not user.mfa_secret:
            return TokenOut(
                access_token="",
                user=UserOut.model_validate(user),
                needs_mfa_setup=True,
                mfa_token=mfa_token,
            )
        # User already has MFA set up, just ask for the code
        return TokenOut(
            access_token="",
            user=UserOut.model_validate(user),
            needs_mfa=True,
            mfa_token=mfa_token,
        )

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


@router.get("/users", response_model=list[UserAdminOut])
async def list_users(
    org_id: str | None = None,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List users. Admin: only their org. Super_admin: all or filter by org_id."""
    from app.models.organization import Organization
    from sqlalchemy.orm import selectinload

    query = select(User).order_by(User.created_at.desc())
    if current_user.role == "admin":
        if not current_user.organization_id:
            return []
        query = query.where(User.organization_id == current_user.organization_id)
    elif current_user.role == "super_admin" and org_id:
        query = query.where(User.organization_id == org_id)

    result = await db.execute(query)
    users = result.scalars().all()
    org_ids = {u.organization_id for u in users if u.organization_id}
    orgs = {}
    if org_ids:
        org_result = await db.execute(select(Organization).where(Organization.id.in_(org_ids)))
        orgs = {str(o.id): o.name for o in org_result.scalars().all()}

    return [
        UserAdminOut(
            id=u.id,
            email=u.email,
            username=u.username,
            full_name=u.full_name,
            role=u.role,
            organization_id=u.organization_id,
            organization_name=orgs.get(str(u.organization_id)) if u.organization_id else None,
            is_active=u.is_active,
            xp_points=u.xp_points or 0,
            level=u.level or 1,
            badges=u.badges or [],
            streak_days=u.streak_days or 0,
            mfa_enabled=u.mfa_enabled or False,
        )
        for u in users
    ]


@router.get("/users/assignable", response_model=list[UserOut])
async def list_assignable_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List users who can be assigned as lead or tester — for project creation. Org-scoped."""
    from sqlalchemy import or_
    query = select(User).where(
        User.is_active == True,
        or_(User.role == "super_admin", User.role == "admin", User.role == "lead", User.role == "tester")
    )
    # Org-scope for non-super_admin
    if current_user.role != "super_admin" and current_user.organization_id:
        query = query.where(User.organization_id == current_user.organization_id)
    result = await db.execute(query)
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserAdminOut)
async def create_user(
    payload: UserCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create user. Admin: in their org only. Super_admin: can set org, create admin with org."""
    role = payload.role or "tester"
    org_id = None
    if payload.organization_id:
        try:
            org_id = uuid.UUID(payload.organization_id)
        except ValueError:
            raise HTTPException(400, "Invalid organization_id")

    if current_user.role == "admin":
        if not current_user.organization_id:
            raise HTTPException(403, "Admin must belong to an organization")
        org_id = current_user.organization_id
        if role == "super_admin":
            raise HTTPException(403, "Only super_admin can create super_admin")
    elif current_user.role == "super_admin":
        if role == "admin" and not org_id:
            raise HTTPException(400, "organization_id required when creating admin")
        if role == "super_admin":
            raise HTTPException(403, "Cannot create another super_admin via API")

    existing = await db.execute(
        select(User).where((User.email == payload.email) | (User.username == payload.username))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Email or username already exists")

    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=role,
        organization_id=org_id,
    )
    db.add(user)
    await db.flush()
    await log_audit(db, "create_user", user_id=str(current_user.id), resource_type="user", resource_id=str(user.id), details={"username": user.username, "role": role})
    await db.commit()
    await db.refresh(user)
    from app.models.organization import Organization
    org_name = None
    if user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = o.scalar_one_or_none()
        org_name = org.name if org else None
    return UserAdminOut(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=org_name,
        is_active=user.is_active,
        xp_points=user.xp_points or 0,
        level=user.level or 1,
        badges=user.badges or [],
        streak_days=user.streak_days or 0,
        mfa_enabled=user.mfa_enabled or False,
    )


@router.get("/users/{user_id}", response_model=UserAdminOut)
async def get_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get user by ID. Admin: only users in their org."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if current_user.role == "admin" and user.organization_id != current_user.organization_id:
        raise HTTPException(403, "Access denied")
    from app.models.organization import Organization
    org_name = None
    if user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = o.scalar_one_or_none()
        org_name = org.name if org else None
    return UserAdminOut(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=org_name,
        is_active=user.is_active,
        xp_points=user.xp_points or 0,
        level=user.level or 1,
        badges=user.badges or [],
        streak_days=user.streak_days or 0,
        mfa_enabled=user.mfa_enabled or False,
    )


@router.patch("/users/{user_id}", response_model=UserAdminOut)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update user — admin only. All fields optional."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if current_user.role == "admin" and user.organization_id != current_user.organization_id:
        raise HTTPException(403, "Access denied")
    if payload.email is not None:
        existing = await db.execute(select(User).where(and_(User.email == payload.email, User.id != user.id)))
        if existing.scalar_one_or_none():
            raise HTTPException(400, "Email already in use")
        user.email = payload.email
    if payload.username is not None:
        existing = await db.execute(select(User).where(and_(User.username == payload.username, User.id != user.id)))
        if existing.scalar_one_or_none():
            raise HTTPException(400, "Username already in use")
        user.username = payload.username
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        if payload.role == "super_admin" and current_user.role != "super_admin":
            raise HTTPException(403, "Only super_admin can assign super_admin role")
        user.role = payload.role
    if payload.organization_id is not None and current_user.role == "super_admin":
        try:
            user.organization_id = uuid.UUID(payload.organization_id) if payload.organization_id else None
        except ValueError:
            raise HTTPException(400, "Invalid organization_id")
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.xp_points is not None:
        user.xp_points = payload.xp_points
    if payload.level is not None:
        user.level = payload.level
    await db.commit()
    await db.refresh(user)
    await log_audit(db, "user_update", user_id=str(current_user.id), details={"target_user_id": str(user_id)})
    from app.models.organization import Organization
    org_name = None
    if user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = o.scalar_one_or_none()
        org_name = org.name if org else None
    return UserAdminOut(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=org_name,
        is_active=user.is_active,
        xp_points=user.xp_points or 0,
        level=user.level or 1,
        badges=user.badges or [],
        streak_days=user.streak_days or 0,
        mfa_enabled=user.mfa_enabled or False,
    )


@router.put("/users/{user_id}/password", response_model=UserAdminOut)
async def update_user_password(
    user_id: str,
    payload: UserPasswordUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Change user password — admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if current_user.role == "admin" and user.organization_id != current_user.organization_id:
        raise HTTPException(403, "Access denied")
    user.hashed_password = hash_password(payload.password)
    await db.commit()
    await db.refresh(user)
    await log_audit(db, "user_password_change", user_id=str(current_user.id), details={"target_user_id": str(user_id)})
    from app.models.organization import Organization
    org_name = None
    if user.organization_id:
        o = await db.execute(select(Organization).where(Organization.id == user.organization_id))
        org = o.scalar_one_or_none()
        org_name = org.name if org else None
    return UserAdminOut(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=org_name,
        is_active=user.is_active,
        xp_points=user.xp_points or 0,
        level=user.level or 1,
        badges=user.badges or [],
        streak_days=user.streak_days or 0,
        mfa_enabled=user.mfa_enabled or False,
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete user — super_admin only. Cannot delete yourself or other super_admins."""
    if str(current_user.id) == user_id:
        raise HTTPException(400, "Cannot delete yourself")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.role == "super_admin":
        raise HTTPException(403, "Cannot delete super_admin user")
    username = user.username
    await db.delete(user)
    await log_audit(db, "delete_user", user_id=str(current_user.id), resource_type="user", resource_id=str(user_id), details={"username": username})
    await db.commit()
    return {"ok": True, "message": f"User {username} deleted successfully"}
