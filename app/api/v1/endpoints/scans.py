"""Code scanning endpoints"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.core.database import get_db
from app.dependencies.auth import verify_api_credentials
from app.models.user import User
from app.services.project_service import ProjectService

class ScanRequest(BaseModel):
    project_path: str = Field(..., description="Path to the project for scanning")
    scan_mode: str = Field(..., description="Scan mode: quick, standard, or deep")

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/submit", status_code=status.HTTP_202_ACCEPTED)
async def submit_scan(
    scan: ScanRequest,
    authenticated_user: User = Depends(verify_api_credentials),
    session: AsyncSession = Depends(get_db),
):
    """
    Submit a project for code scanning (body JSON).
    Stores project in DB and returns success message.
    """
    await ProjectService.create_project(session, authenticated_user, scan.project_path)
    return {
        "message": f"Project folder '{scan.project_path}' registered successfully.",
        "project_path": scan.project_path,
        "scan_mode": scan.scan_mode,
    }
