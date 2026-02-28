"""Pytest fixtures for API tests."""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.core.database import get_db, Base
from app.core.security import hash_password, create_access_token
from app.models.user import User
import os

# Use test DB if available
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://navigator:navigator_secure_password@127.0.0.1:5433/navigator_test")
if "navigator_test" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("/navigator", "/navigator_test")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def db_engine():
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    async_session = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session


@pytest.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
async def admin_user(db_session):
    user = User(
        email="admin@test.com",
        username="admin_test",
        full_name="Admin Test",
        hashed_password=hash_password("admin123"),
        role="admin",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def admin_token(admin_user):
    return create_access_token({"sub": str(admin_user.id), "role": "admin"})
