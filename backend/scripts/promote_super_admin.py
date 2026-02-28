#!/usr/bin/env python3
"""Ensure super_admin exists and admin stays as org admin. Run after seed_db."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import hash_password


async def main():
    async with AsyncSessionLocal() as db:
        # 1. Ensure superadmin exists (platform owner)
        r = await db.execute(select(User).where(User.username == "superadmin"))
        superadmin = r.scalar_one_or_none()
        if not superadmin:
            superadmin = User(
                email="superadmin@vapt.local",
                username="superadmin",
                full_name="Platform Super Admin",
                hashed_password=hash_password("SuperAdmin@2026!"),
                role="super_admin",
                xp_points=0,
                level=1,
            )
            db.add(superadmin)
            print("Created super_admin: superadmin / SuperAdmin@2026!")
        else:
            superadmin.role = "super_admin"

        # 2. Demote admin back to org admin if it was wrongly promoted
        r2 = await db.execute(select(User).where(User.username == "admin"))
        admin = r2.scalar_one_or_none()
        if admin and admin.role == "super_admin":
            admin.role = "admin"
            print("Demoted admin to org admin: admin / Admin@2026!")

        await db.commit()

    print("\nCredentials:")
    print("  Super Admin (platform): superadmin / SuperAdmin@2026!")
    print("  Org Admin:             admin / Admin@2026!")


if __name__ == "__main__":
    asyncio.run(main())
