"""SAST (notebook-agent) endpoints

Expose endpoints to start SAST runs and download completed reports.

POST /start - creates a scheduled SASTReport and schedules a background run.
GET /report/{report_id} - download a completed JSON report (scoped to business).
"""
from typing import Optional
import json
from pathlib import Path
from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder

from app.dependencies.auth import verify_api_credentials
from app.core.database import get_db, AsyncSessionLocal
from app.services.llm_service import get_user_llm_setting
from app.services.project_service import ProjectService
from app.services.sast_service import SASTService
from app.models.user import User

# Import the notebook agent runner (run_sast) if available
try:
    from agent import run_sast  # repo-root agent.py
except Exception:  # pragma: no cover - import guard for test/runtime
    run_sast = None


router = APIRouter()  # parent router mounts under /sast


class SastStartRequest(BaseModel):
    start: bool


async def _bg_run_sast(
    report_id: str,
    provider: str,
    api_key: Optional[str],
    model: Optional[str],
    local_base_url: Optional[str] = None,
    local_model: Optional[str] = None,
):
    """Background wrapper that updates DB and calls the notebook run_sast function.

    The background task will:
    - mark report as running
    - run the notebook agent (in a threadpool to avoid blocking the event loop)
    - persist the JSON file under reports/{business_id}/{report_id}.json
    - update the DB record to completed or failed
    """
    if run_sast is None:
        print("[sast] run_sast is not available (import failed)")
        # mark failed if possible
        try:
            async with AsyncSessionLocal() as db:
                await SASTService.mark_failed(db, report_id, "run_sast not available")
        except Exception:
            pass
        return

    # Create a fresh async session for background work
    async with AsyncSessionLocal() as db:
        try:
            report = await SASTService.get_report_by_id(db, report_id)
            if not report:
                print(f"[sast] report {report_id} not found")
                return

            # mark running
            await SASTService.mark_running(db, report_id)

            project_path = str(getattr(report, "project_path", ""))
            business_id = str(getattr(report, "business_id", ""))
            print(f"[sast] background start: {project_path} using {provider}:{model}")

            # run in threadpool to avoid blocking the event loop
            final = await run_in_threadpool(
                run_sast, project_path, provider, api_key or "", model or "", local_base_url, local_model
            )

            findings = final.get("findings") if isinstance(final, dict) else None

            # Prepare final JSON and ensure it's JSON-serializable
            final_json = final if isinstance(final, dict) else {"result": str(final)}
            final_safe = jsonable_encoder(final_json)

            reports_dir = Path("reports") / business_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            file_path = reports_dir / f"{report_id}.json"
            try:
                with file_path.open("w", encoding="utf-8") as fh:
                    json.dump(final_safe, fh, ensure_ascii=False, indent=2)
            except Exception as fh_exc:
                # Persist failure
                await SASTService.mark_failed(db, report_id, f"failed to write report file: {fh_exc}")
                print(f"[sast] failed to write report file: {fh_exc}")
                return

            findings_count = len(findings) if findings and isinstance(findings, (list, tuple)) else 0
            # mark completed (store the JSON-safe structure)
            await SASTService.mark_completed(db, report_id, findings_count, final_safe, str(file_path))
            print(f"[sast] background finished: findings={findings_count} file={file_path}")
        except Exception as exc:  # pragma: no cover - runtime error handling
            try:
                await SASTService.mark_failed(db, report_id, str(exc))
            except Exception:
                pass
            print(f"[sast] error during background run: {exc}")


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_sast(
    body: SastStartRequest,
    background_tasks: BackgroundTasks,
    authenticated_user: User = Depends(verify_api_credentials),
    db: AsyncSession = Depends(get_db),
    project_id: Optional[str] = None,
):
    """Schedule the notebook-style SAST scan for the authenticated user.

    Body example: {"start": true}
    """
    if not body.start:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="`start` must be true to run SAST")

    if run_sast is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="SAST runner not available")

    # Load LLM setting
    user_id = getattr(authenticated_user, "id")
    # user_id may be a SQLAlchemy-backed attribute; cast for the service call
    llm_setting = await get_user_llm_setting(db, int(user_id))  # type: ignore[arg-type]
    if not llm_setting:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LLM setting not configured for user")

    # Resolve project: if project_id provided, use that project (if owned by user), else pick most-recent
    projects = await ProjectService.get_projects_for_user(db, authenticated_user)
    if not projects:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No project registered for user")

    project = None
    if project_id is not None:
        # find matching project id among the user's projects (ids are UUID strings)
        for p in projects:
            if str(getattr(p, "id", "")) == project_id:
                project = p
                break
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project id not found for user")
    else:
        project = projects[-1]

    project_path = str(getattr(project, "project_path", None))
    if not project_path:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project record missing path")

    provider = str(getattr(llm_setting, "provider", ""))
    if provider == "gapgpt":
        gapgpt_api_key = getattr(llm_setting, "gapgpt_api_key", None)
        gapgpt_model = getattr(llm_setting, "gapgpt_model", None)
        api_key = str(gapgpt_api_key) if gapgpt_api_key is not None else None
        model = str(gapgpt_model) if gapgpt_model is not None else None
        local_base = None
        local_model = None
    else:
        api_key = None
        local_model_name = getattr(llm_setting, "local_model_name", None)
        local_base_url = getattr(llm_setting, "local_base_url", None)
        model = str(local_model_name) if local_model_name is not None else None
        local_base = str(local_base_url) if local_base_url is not None else None
        local_model = str(local_model_name) if local_model_name is not None else None

    # Create scheduled report record with business scoping from authenticated_user
    business_id = getattr(authenticated_user, "business_id", None)
    if not business_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authenticated user missing business_id")

    sast_report = await SASTService.create_scheduled_report(db, business_id, project_path, provider)

    # Schedule background task which will use its own DB session
    # Cast values to plain python types to avoid SQLAlchemy Column objects getting passed into the background task
    background_tasks.add_task(
        _bg_run_sast,
        str(sast_report.id),
        str(provider),
        str(api_key) if api_key is not None else None,
        str(model) if model is not None else None,
        str(local_base) if local_base is not None else None,
        str(local_model) if local_model is not None else None,
    )

    return {
        "message": "SAST scan scheduled",
        "report_id": str(sast_report.id),
        "status": "scheduled",
    }


@router.get("/report/{report_id}")
async def download_report(
    report_id: str,
    authenticated_user: User = Depends(verify_api_credentials),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Download a completed SAST JSON report for the same business only.

    Requires the same authenticated business context. Returns 404 if not found,
    403 if cross-business access is attempted, and 409 if the report is not completed yet.
    """
    business_id = getattr(authenticated_user, "business_id", None)
    if not business_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing business identifier")

    report = await SASTService.get_report_by_id_for_business(db, report_id, business_id)
    if not report:
        # Could be not found or cross-business — return 404 to avoid leaking existence
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    status_val = str(getattr(report, "status", ""))
    if status_val != "completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Report not ready: status={status_val}")

    file_path_str = getattr(report, "report_file_path", None)
    if not file_path_str:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Report file missing")

    file_path = Path(str(file_path_str))
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on disk")

    return FileResponse(path=str(file_path), media_type="application/json", filename=f"{report_id}.json")
