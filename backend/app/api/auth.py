"""Authentication API."""
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.services.audit_service import log_audit
from app.core.security import hash_password, verify_password, create_access_token, decode_token
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, UserOut, TokenOut

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
    if current_user.role != "admin":
        raise HTTPException(403, "Admin access required")
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
    await log_audit(db, "login", user_id=str(user.id), ip_address=request.client.host if request.client else None, user_agent=request.headers.get("user-agent"))
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
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


@router.get("/users", response_model=list[UserOut])
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users — admin only."""
    result = await db.execute(select(User).where(User.is_active == True))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.get("/users/assignable", response_model=list[UserOut])
async def list_assignable_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List users who can be assigned as lead or tester — for project creation. Tester+ can access."""
    from sqlalchemy import or_
    result = await db.execute(
        select(User).where(
            User.is_active == True,
            or_(User.role == "admin", User.role == "lead", User.role == "tester")
        )
    )
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserOut)
async def create_user(
    payload: UserCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create user — admin only. Self-registration is disabled."""
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
        role=payload.role or "tester",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)
