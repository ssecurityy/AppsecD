"""MFA API — TOTP setup, verification, and login completion.

Supports Google Authenticator and Microsoft Authenticator.
Available for ALL users (not just admin). Super admin can enable/disable MFA for any user.

MFA Flow:
1. Super admin enables MFA for user → sets mfa_enabled=True, mfa_secret=None
2. User logs in → gets needs_mfa_setup=True + mfa_token (because no secret yet)
3. Frontend calls /mfa/setup-with-token to get QR code
4. User scans QR, enters code → calls /mfa/complete-setup to verify & get access token
5. Next login → gets needs_mfa=True (secret exists), enters code → /mfa/complete-login

Reset flow: Super admin resets MFA → clears mfa_secret, keeps mfa_enabled=True
→ user must set up again on next login (step 2-4 above)
"""
import pyotp
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.api.auth import get_current_user, require_super_admin
from app.core.security import decode_token, create_access_token
from app.models.user import User
from app.schemas.user import TokenOut, UserOut

router = APIRouter(prefix="/mfa", tags=["mfa"])


async def get_current_user_from_mfa_token(token: str, db: AsyncSession) -> User | None:
    """Decode mfa_pending token and return user. Used by complete-login and setup-with-token."""
    payload = decode_token(token)
    if not payload or payload.get("purpose") != "mfa_pending":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


class MfaSetupOut(BaseModel):
    secret: str
    qr_uri: str


class MfaVerifyRequest(BaseModel):
    code: str


class MfaCompleteLoginPayload(BaseModel):
    mfa_token: str
    code: str


class MfaSetupWithTokenPayload(BaseModel):
    mfa_token: str


class MfaCompleteSetupPayload(BaseModel):
    mfa_token: str
    code: str


class MfaEnableForUserRequest(BaseModel):
    user_id: str
    enable: bool


class MfaResetForUserRequest(BaseModel):
    user_id: str


# ═══════════════════════════════════════════════════════════
# Login-time MFA endpoints (use mfa_token, no full auth)
# ═══════════════════════════════════════════════════════════

@router.post("/setup-with-token")
async def mfa_setup_with_token(
    payload: MfaSetupWithTokenPayload,
    db: AsyncSession = Depends(get_db),
):
    """Generate MFA secret during login flow. Used when user needs to set up MFA for the first time.
    Requires mfa_token from login response (not full auth).
    Works with Google Authenticator and Microsoft Authenticator."""
    user = await get_current_user_from_mfa_token(payload.mfa_token, db)
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid or expired MFA token")
    # Allow both: (1) first-time setup when admin/super_admin is required to set up (mfa_enabled=False),
    # and (2) re-setup when admin enabled MFA for user (mfa_enabled=True, they get mfa_token on login).

    # Generate new secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    issuer = "AppSecD"
    qr_uri = totp.provisioning_uri(name=user.email, issuer_name=issuer)

    # Store secret temporarily — user must verify with code to finalize
    user.mfa_secret = secret
    await db.commit()

    return {"secret": secret, "qr_uri": qr_uri}


@router.post("/complete-setup", response_model=TokenOut)
async def mfa_complete_setup(
    payload: MfaCompleteSetupPayload,
    db: AsyncSession = Depends(get_db),
):
    """Complete MFA setup during login. User scanned QR code and enters TOTP code to verify.
    On success, returns full access token (user is now logged in)."""
    user = await get_current_user_from_mfa_token(payload.mfa_token, db)
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid or expired MFA token")
    if not user.mfa_secret:
        raise HTTPException(400, "Run /mfa/setup-with-token first to get QR code")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(400, "Invalid verification code. Please try again.")

    # MFA setup is now complete — secret verified
    user.mfa_enabled = True
    await db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.post("/complete-login", response_model=TokenOut)
async def mfa_complete_login(
    payload: MfaCompleteLoginPayload,
    db: AsyncSession = Depends(get_db),
):
    """Complete login after MFA. For users who already have MFA set up.
    Requires mfa_token from login response and TOTP code."""
    user = await get_current_user_from_mfa_token(payload.mfa_token, db)
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid or expired MFA token")
    if not getattr(user, "mfa_enabled", False) or not user.mfa_secret:
        raise HTTPException(400, "MFA not set up for this user")
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(401, "Invalid verification code")
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


# ═══════════════════════════════════════════════════════════
# Authenticated user MFA endpoints (self-service)
# ═══════════════════════════════════════════════════════════

@router.get("/setup")
async def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate MFA secret for setup. For authenticated users setting up MFA voluntarily.
    Works with Google Authenticator and Microsoft Authenticator."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    issuer = "AppSecD"
    qr_uri = totp.provisioning_uri(name=current_user.email, issuer_name=issuer)
    # Store secret temporarily - user must verify to enable
    current_user.mfa_secret = secret
    await db.commit()
    return {"secret": secret, "qr_uri": qr_uri}


@router.post("/verify")
async def mfa_verify(
    payload: MfaVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and enable MFA. For authenticated users (self-service)."""
    if not current_user.mfa_secret:
        raise HTTPException(400, "Run /mfa/setup first")
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(400, "Invalid code. Please try again.")
    current_user.mfa_enabled = True
    await db.commit()
    return {"enabled": True, "message": "MFA enabled successfully"}


@router.post("/disable")
async def mfa_disable(
    payload: MfaVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA (requires current TOTP code)."""
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise HTTPException(400, "MFA not enabled")
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(400, "Invalid code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.commit()
    return {"enabled": False, "message": "MFA disabled successfully"}


@router.get("/status")
async def mfa_status(current_user: User = Depends(get_current_user)):
    """Check if current user has MFA enabled."""
    return {
        "mfa_enabled": getattr(current_user, "mfa_enabled", False),
        "mfa_setup_complete": bool(current_user.mfa_secret) if current_user.mfa_enabled else False,
    }


# ═══════════════════════════════════════════════════════════
# Super Admin MFA management
# ═══════════════════════════════════════════════════════════

@router.post("/admin/enable-for-user")
async def admin_enable_mfa_for_user(
    payload: MfaEnableForUserRequest,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Super admin: enable or disable MFA requirement for a user.
    When enabling, does NOT generate a secret — user will be prompted to set up MFA
    (scan QR code) on their next login."""
    result = await db.execute(select(User).where(User.id == payload.user_id))
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(404, "User not found")

    if payload.enable:
        # Just mark MFA as required — do NOT generate secret
        # User will set up on next login via /mfa/setup-with-token
        target_user.mfa_enabled = True
        # Clear any old secret so user must set up fresh
        target_user.mfa_secret = None
    else:
        target_user.mfa_enabled = False
        target_user.mfa_secret = None

    await db.commit()
    return {
        "user_id": payload.user_id,
        "mfa_enabled": target_user.mfa_enabled,
        "message": f"MFA {'enabled' if payload.enable else 'disabled'} for user {target_user.username}",
    }


@router.post("/admin/reset-mfa")
async def admin_reset_mfa(
    payload: MfaResetForUserRequest,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Super admin: reset MFA for a user who lost access to their authenticator app.
    Clears the secret but keeps MFA enabled — user will be prompted to set up
    a new QR code on their next login."""
    result = await db.execute(select(User).where(User.id == payload.user_id))
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(404, "User not found")

    # Clear secret but keep MFA enabled — forces re-setup on next login
    target_user.mfa_secret = None
    await db.commit()
    return {
        "user_id": payload.user_id,
        "mfa_enabled": target_user.mfa_enabled,
        "message": f"MFA reset for user {target_user.username}. They will set up a new authenticator on next login.",
    }
