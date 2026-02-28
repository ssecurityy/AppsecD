"""AppSecD — FastAPI Backend."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.config import get_settings
from app.api import api_router

settings = get_settings()
app = FastAPI(
    title="AppSecD API",
    description="Enterprise Application Security Testing & Vulnerability Management Platform",
    version="2.0.0",
)

from app.core.limiter import limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"app": "AppSecD", "version": "2.0.0", "docs": "/docs"}


@app.get("/health")
async def health():
    """Liveness: app is running."""
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready():
    """Readiness: app can serve traffic (DB + Redis reachable)."""
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import text
    ok = {"status": "ready", "database": False, "redis": False}
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        ok["database"] = True
    except Exception:
        pass
    try:
        from app.core.redis_client import get_redis
        r = await get_redis()
        await r.ping()
        ok["redis"] = True
    except Exception:
        pass
    if not ok["database"]:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=ok)
    return ok
