#!/usr/bin/env python3
"""Reset superadmin password to default and disable MFA. Run from backend dir."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import hash_password

DEFAULT_PASSWORD = "SuperAdmin@2026!"


async def main():
    async with AsyncSessionLocal() as db:
        r = await db.execute(select(User).where(User.username == "superadmin"))
        user = r.scalar_one_or_none()
        if not user:
            print("ERROR: User 'superadmin' not found. Run seed_db or promote_super_admin first.")
            sys.exit(1)
        user.hashed_password = hash_password(DEFAULT_PASSWORD)
        user.mfa_enabled = False
        user.mfa_secret = None
        await db.commit()
        print("Superadmin reset successfully.")
        print(f"  Username: superadmin")
        print(f"  Password: {DEFAULT_PASSWORD}")
        print("  MFA: disabled (cleared)")


if __name__ == "__main__":
    asyncio.run(main())
