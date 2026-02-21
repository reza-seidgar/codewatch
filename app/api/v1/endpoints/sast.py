"""SAST (notebook-agent) endpoints

Expose a simple POST endpoint to start the notebook-style SAST agent
for the authenticated user. The handler schedules the scan as a background
task so the request returns quickly.
"""
from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import verify_api_credentials
from app.core.database import get_db
from app.services.llm_service import get_user_llm_setting
from app.services.project_service import ProjectService
from app.models.user import User

# Import the notebook agent runner (run_sast)
try:
    # agent.py is at repo root and exposes run_sast
    from agent import run_sast
except Exception:  # pragma: no cover - import guard for test/runtime
    run_sast = None


"""SAST (notebook-agent) endpoints

Expose a simple POST endpoint to start the notebook-style SAST agent
for the authenticated user. The handler schedules the scan as a background
task so the request returns quickly.
"""
from typing import Optional

from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import verify_api_credentials
from app.core.database import get_db
from app.services.llm_service import get_user_llm_setting
from app.services.project_service import ProjectService
from app.models.user import User

# Import the notebook agent runner (run_sast) if available
try:
    from agent import run_sast  # repo-root agent.py
except Exception:  # pragma: no cover - import guard for test/runtime
    run_sast = None


router = APIRouter()  # parent router mounts under /sast


class SastStartRequest(BaseModel):
    start: bool


def _bg_run_sast(
    project_path: str,
    provider: str,
    api_key: Optional[str],
    model: Optional[str],
    local_base_url: Optional[str] = None,
    local_model: Optional[str] = None,
):
    """Background wrapper that calls the notebook run_sast function.

    This intentionally prints high-level progress to stdout. In a later
    iteration we'll persist run state and results to the database.
    """
    if run_sast is None:
        print("[sast] run_sast is not available (import failed)")
        return

    try:
        print(f"[sast] background start: {project_path} using {provider}:{model}")
        final = run_sast(project_path, provider, api_key or "", model or "", local_base_url, local_model)
        # final may be a State object or dict depending on agent; best-effort log
        findings = final.get("findings") if isinstance(final, dict) else None
        print(f"[sast] background finished: findings={len(findings) if findings else 'unknown'}")
    except Exception as exc:  # pragma: no cover - runtime error handling
        print(f"[sast] error during background run: {exc}")


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_sast(
    body: SastStartRequest,
    background_tasks: BackgroundTasks,
    authenticated_user: User = Depends(verify_api_credentials),
    db: AsyncSession = Depends(get_db),
):
    """Schedule the notebook-style SAST scan for the authenticated user.

    Body example: {"start": true}
    """
    if not body.start:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="`start` must be true to run SAST")

    if run_sast is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="SAST runner not available")

    # Load LLM setting
    llm_setting = await get_user_llm_setting(db, authenticated_user.id)
    if not llm_setting:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LLM setting not configured for user")

    # Pick most-recent project
    projects = await ProjectService.get_projects_for_user(db, authenticated_user)
    if not projects:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No project registered for user")

    project = projects[-1]
    project_path = getattr(project, "project_path", None)
    if not project_path:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project record missing path")

    provider = llm_setting.provider
    if provider == "gapgpt":
        api_key = llm_setting.gapgpt_api_key
        model = llm_setting.gapgpt_model
        local_base = None
        local_model = None
    else:
        api_key = None
        model = llm_setting.local_model_name
        local_base = llm_setting.local_base_url
        local_model = llm_setting.local_model_name

    # Schedule background task
    background_tasks.add_task(
        _bg_run_sast,
        project_path,
        provider,
        api_key,
        model,
        local_base,
        local_model,
    )

    return {
        "message": "SAST scan scheduled",
        "project_path": project_path,
        "provider": provider,
        "status": "scheduled",
    }
