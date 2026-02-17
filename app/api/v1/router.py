"""API v1 router combining all endpoints"""
from fastapi import APIRouter

from app.api.v1.endpoints import users, scans, llm_settings

router = APIRouter(prefix="/api/v1")

# Include all endpoint routers
router.include_router(users.router)
router.include_router(scans.router)
# Mount llm settings under /api/v1/llm
router.include_router(llm_settings.router, prefix="/llm", tags=["LLM Settings"])

__all__ = ["router"]
