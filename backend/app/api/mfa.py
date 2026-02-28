"""MFA API — TOTP setup and verification for admin users."""
import pyotp
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.api.auth import get_current_user, require_admin
from app.models.user import User

router = APIRouter(prefix="/mfa", tags=["mfa"])


class MfaSetupOut(BaseModel):
    secret: str
    qr_uri: str
    backup_codes: list[str]


class MfaVerifyRequest(BaseModel):
    code: str


@router.get("/setup")
async def mfa_setup(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Generate MFA secret for setup. Admin only."""
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
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and enable MFA."""
    if not current_user.mfa_secret:
        raise HTTPException(400, "Run /mfa/setup first")
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(400, "Invalid code")
    current_user.mfa_enabled = True
    await db.commit()
    return {"enabled": True}


@router.post("/disable")
async def mfa_disable(
    payload: MfaVerifyRequest,
    current_user: User = Depends(require_admin),
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
    return {"enabled": False}


@router.get("/status")
async def mfa_status(current_user: User = Depends(get_current_user)):
    """Check if current user has MFA enabled."""
    return {"mfa_enabled": getattr(current_user, "mfa_enabled", False)}
