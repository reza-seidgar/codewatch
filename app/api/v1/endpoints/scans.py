"""Code scanning endpoints"""
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.core.database import get_db
from app.dependencies.auth import verify_api_credentials
from app.models.user import User
from app.services.project_service import ProjectService
from app.core.llm_client import get_llm_client, LLMError
from app.agents.analyzer_agent import analyze_project, AnalyzerError
import uuid

class ScanRequest(BaseModel):
    project_path: str = Field(..., description="Path to the project for scanning")
    scan_mode: str = Field(..., description="Scan mode: quick, standard, or deep")

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/submit", status_code=status.HTTP_200_OK)
async def submit_scan(
    scan: ScanRequest,
    authenticated_user: User = Depends(verify_api_credentials),
    session: AsyncSession = Depends(get_db),
):
    """
    Submit a project for code scanning (body JSON).
    Stores project in DB and returns success message.
    """
    # Persist project
    project = await ProjectService.create_project(session, authenticated_user, scan.project_path)

    # Build LLM client for this user
    try:
        # authenticated_user.id is a SQLAlchemy attribute; ignore static type checks here
        llm_client = await get_llm_client(session, int(authenticated_user.id))  # type: ignore[arg-type]
    except ValueError:
        # User has no LLMSetting configured
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No LLM settings configured for user. Please configure /api/v1/llm/settings first.")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    # Run analyzer (may raise AnalyzerError)
    try:
        analysis = await analyze_project(scan.project_path, llm_client)
    except AnalyzerError as ae:
        # Analyzer failed; return project registered but mark as error
        return {
            "scan_id": uuid.uuid4().hex,
            "status": "error",
            "project_path": scan.project_path,
            "error": str(ae),
        }

    # Successful analysis
    return {
        "scan_id": uuid.uuid4().hex,
        "status": "analyzed",
        "project_path": scan.project_path,
        "analysis": analysis.model_dump(),
    }
