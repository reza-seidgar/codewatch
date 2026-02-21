"""Agent control endpoints

This module exposes a simple route to start the analyzer agent for the
authenticated user. The client sends a boolean `start: true` and the server
loads the user's LLMSetting and the most-recently-registered Project and runs
the analyzer against that project path.
"""
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import verify_api_credentials
from app.core.database import get_db
from app.models.user import User
from app.services.project_service import ProjectService
from app.core.llm_client import get_llm_client, LLMError
from app.agents.analyzer_agent import analyze_project, AnalyzerError

import uuid


router = APIRouter(prefix="/agent", tags=["agent"])


class AgentStartRequest(BaseModel):
    start: bool = Field(..., description="Set to true to start the agent run")


@router.post("/start", status_code=status.HTTP_200_OK)
async def start_agent(
    body: AgentStartRequest,
    authenticated_user: User = Depends(verify_api_credentials),
    session: AsyncSession = Depends(get_db),
):
    """Start an analyzer agent run for the authenticated user.

    The endpoint will:
    - require `start: true` in the JSON body
    - fetch the user's LLMSetting and most-recent Project
    - run `analyze_project(project_path, llm_client)` and return the analysis
    """
    if not body.start:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Set 'start' to true to begin an agent run")

    # Build LLM client for this user
    try:
        llm_client = await get_llm_client(session, int(authenticated_user.id))  # type: ignore[arg-type]
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No LLM settings configured for user. Please configure /api/v1/llm/settings first.")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    # Fetch user's projects and pick most-recent
    projects = await ProjectService.get_projects_for_user(session, authenticated_user)
    if not projects:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No projects registered for this user. Submit a scan first via /api/v1/scans/submit")

    # Use the latest project (last in list)
    project = projects[-1]
    project_path = getattr(project, "project_path", None)
    if not project_path:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Selected project has no project_path")

    # Run analyzer (may raise AnalyzerError)
    try:
        analysis = await analyze_project(project_path, llm_client)
    except AnalyzerError as ae:
        return {
            "agent_run_id": uuid.uuid4().hex,
            "status": "error",
            "project_path": project_path,
            "error": str(ae),
        }
    except LLMError as le:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"LLM error: {le}")

    return {
        "agent_run_id": uuid.uuid4().hex,
        "status": "completed",
        "project_path": project_path,
        "analysis": analysis.model_dump(),
    }
