"""AppSecD — FastAPI Backend."""
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.config import get_settings
from app.api import api_router

logger = logging.getLogger(__name__)
settings = get_settings()

app = FastAPI(
    title="AppSecD API",
    description="Enterprise Application Security Testing & Vulnerability Management Platform",
    version="2.0.0",
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
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

app.include_router(api_router, prefix="/api")  # Single API surface: /api/auth, /api/projects, etc.


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Return generic 500 to avoid leaking stack traces or module names."""
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.on_event("startup")
async def startup_cve_auto_sync():
    """Start background CVE auto-sync and WebSocket Redis listener on app startup."""
    import asyncio
    from app.api.websocket import start_redis_ws_listener
    try:
        start_redis_ws_listener()
        logger.info("WebSocket Redis pub/sub listener started")
    except Exception as e:
        logger.warning("WebSocket Redis listener not started: %s", e)

    async def _cve_sync_loop():
        """Periodically sync CVEs from NVD, GitHub, CIRCL every 6 hours."""
        await asyncio.sleep(30)  # Wait 30s for DB to be ready
        while True:
            try:
                from app.core.database import AsyncSessionLocal
                from app.api.security_intel import _sync_from_nvd, _sync_from_github, _sync_from_circl
                async with AsyncSessionLocal() as db:
                    total = 0
                    # NVD — last 30 days
                    try:
                        count = await _sync_from_nvd(db, "", 30)
                        total += count
                        logger.info("CVE auto-sync NVD: %d new/updated", count)
                    except Exception as e:
                        logger.warning("CVE auto-sync NVD failed: %s", e)

                    # GitHub Advisories
                    try:
                        count = await _sync_from_github(db, "", 30)
                        total += count
                        logger.info("CVE auto-sync GitHub: %d new/updated", count)
                    except Exception as e:
                        logger.warning("CVE auto-sync GitHub failed: %s", e)

                    # CIRCL
                    try:
                        count = await _sync_from_circl(db, "", 30)
                        total += count
                        logger.info("CVE auto-sync CIRCL: %d new/updated", count)
                    except Exception as e:
                        logger.warning("CVE auto-sync CIRCL failed: %s", e)

                    if total > 0:
                        logger.info("CVE auto-sync complete: %d total CVEs synced", total)
            except Exception as e:
                logger.warning("CVE auto-sync cycle failed: %s", e)

            await asyncio.sleep(6 * 3600)  # Run every 6 hours

    asyncio.create_task(_cve_sync_loop())


@app.get("/")
async def root():
    return {"app": "AppSecD", "version": "2.0.0"}


@app.get("/health")
async def health():
    """Liveness: app is running."""
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready(request: Request):
    """Readiness: app can serve traffic. Internal details only when docs_enabled or from loopback."""
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import text
    client = (request.client.host if request.client else None) or ""
    show_internal = settings.docs_enabled or client in ("127.0.0.1", "::1", "localhost")
    ok = {"status": "ready"}
    if show_internal:
        ok["database"] = False
        ok["redis"] = False
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
        if not ok.get("database"):
            return JSONResponse(status_code=503, content=ok)
    return ok
