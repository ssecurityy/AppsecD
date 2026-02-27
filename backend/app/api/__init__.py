from fastapi import APIRouter
from .auth import router as auth_router
from .projects import router as projects_router
from .test_cases import router as testcases_router
from .findings import router as findings_router
from .payloads import router as payloads_router
from .reports import router as reports_router
from .evidence import router as evidence_router
from .badges import router as badges_router
from .ai_assist import router as ai_assist_router
from .audit import router as audit_router
from .mfa import router as mfa_router
from .websocket import router as websocket_router
from .organizations import router as organizations_router
from .settings import router as settings_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(reports_router)
api_router.include_router(evidence_router)
api_router.include_router(badges_router)
api_router.include_router(ai_assist_router)
api_router.include_router(audit_router)
api_router.include_router(mfa_router)
api_router.include_router(websocket_router)
api_router.include_router(organizations_router)
api_router.include_router(settings_router)
api_router.include_router(testcases_router)
api_router.include_router(findings_router)
api_router.include_router(payloads_router)
