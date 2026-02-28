"""API tests for dashboard functionality."""
import pytest
from httpx import AsyncClient


@pytest.mark.anyio
async def test_health(client: AsyncClient):
    """Health endpoint returns ok."""
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_root(client: AsyncClient):
    """Root returns app info."""
    r = await client.get("/")
    assert r.status_code == 200
    assert "VAPT Navigator" in r.json()["app"]


@pytest.mark.anyio
async def test_login_invalid(client: AsyncClient):
    """Login with invalid credentials returns 401."""
    r = await client.post("/auth/login", json={"username": "nonexistent", "password": "wrong"})
    assert r.status_code == 401


@pytest.mark.anyio
async def test_login_success(client: AsyncClient, admin_user, db_session):
    """Login with valid credentials returns token."""
    await db_session.commit()
    r = await client.post("/auth/login", json={"username": "admin_test", "password": "admin123"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin_test"
    assert data["user"]["role"] == "admin"


@pytest.mark.anyio
async def test_me_unauthorized(client: AsyncClient):
    """Me without token returns 401."""
    r = await client.get("/auth/me")
    assert r.status_code == 401


@pytest.mark.anyio
async def test_me_authorized(client: AsyncClient, admin_token):
    """Me with valid token returns user."""
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "admin_test"


@pytest.mark.anyio
async def test_list_users_requires_admin(client: AsyncClient):
    """List users without auth returns 401."""
    r = await client.get("/auth/users")
    assert r.status_code == 401


@pytest.mark.anyio
async def test_list_users_admin(client: AsyncClient, admin_token, admin_user, db_session):
    """Admin can list users."""
    await db_session.commit()
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    r = await client.get("/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    users = r.json()
    assert isinstance(users, list)
    assert len(users) >= 1
