"""Service layer for SASTReport persistence and updates."""
from typing import Optional
import json
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException, status
from fastapi.encoders import jsonable_encoder

from app.models.sast_report import SASTReport


class SASTService:
    @staticmethod
    async def create_scheduled_report(db: AsyncSession, business_id: str, project_path: str, provider: str) -> SASTReport:
        report_id = str(uuid4())
        new = SASTReport(
            id=report_id,
            business_id=business_id,
            project_path=project_path,
            provider=provider,
            status="scheduled",
        )
        db.add(new)
        try:
            await db.commit()
            await db.refresh(new)
            return new
        except Exception as exc:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create SAST report") from exc

    @staticmethod
    async def mark_running(db: AsyncSession, report_id: str) -> None:
        stmt = await db.execute(select(SASTReport).where(SASTReport.id == report_id))
        report = stmt.scalars().first()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        setattr(report, "status", "running")
        db.add(report)
        await db.commit()

    @staticmethod
    async def mark_completed(db: AsyncSession, report_id: str, findings_count: int, report_json: dict, report_file_path: str) -> None:
        stmt = await db.execute(select(SASTReport).where(SASTReport.id == report_id))
        report = stmt.scalars().first()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        setattr(report, "status", "completed")
        setattr(report, "findings_count", findings_count)
        try:
            # Ensure a JSON-serializable structure (handles pydantic models, dataclasses, enums, datetimes, etc.)
            safe = jsonable_encoder(report_json)
            setattr(report, "report_json", json.dumps(safe, ensure_ascii=False))
        except Exception:
            # Fallback to string representation if encoding fails
            setattr(report, "report_json", str(report_json))

        setattr(report, "report_file_path", report_file_path)
        db.add(report)
        await db.commit()

    @staticmethod
    async def mark_failed(db: AsyncSession, report_id: str, error_info: str) -> None:
        stmt = await db.execute(select(SASTReport).where(SASTReport.id == report_id))
        report = stmt.scalars().first()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        setattr(report, "status", "failed")
        # store error in report_json for diagnostics (ensure JSON-safe)
        try:
            safe = jsonable_encoder({"error": str(error_info)})
            setattr(report, "report_json", json.dumps(safe, ensure_ascii=False))
        except Exception:
            setattr(report, "report_json", str(error_info))

        db.add(report)
        await db.commit()

    @staticmethod
    async def get_report_by_id_for_business(db: AsyncSession, report_id: str, business_id: str) -> Optional[SASTReport]:
        stmt = await db.execute(select(SASTReport).where(SASTReport.id == report_id, SASTReport.business_id == business_id))
        return stmt.scalars().first()

    @staticmethod
    async def get_report_by_id(db: AsyncSession, report_id: str) -> Optional[SASTReport]:
        stmt = await db.execute(select(SASTReport).where(SASTReport.id == report_id))
        return stmt.scalars().first()
