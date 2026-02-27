"""Badges API — list badge definitions."""
from fastapi import APIRouter, Depends
from app.api.auth import get_current_user
from app.services.badge_service import BADGES

router = APIRouter(prefix="/badges", tags=["badges"])


@router.get("")
async def list_badges():
    """List all badge definitions."""
    return [
        {"id": k, "name": v["name"], "icon": v["icon"], "trigger": v["trigger"]}
        for k, v in BADGES.items()
    ]
