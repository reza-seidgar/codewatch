"""SASTReport SQLAlchemy model"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Index
from sqlalchemy.sql import func

from app.core.database import Base


class SASTReport(Base):
    """Persistent record for a SAST run.

    Fields mirror the user's request: uuid id, business_id, project_path,
    provider, status, findings_count, report_json (text), report_file_path,
    created_at, updated_at.
    """

    __tablename__ = "sast_reports"

    # Use a string UUID (36 chars) for portability across DB backends
    id = Column(String(36), primary_key=True, nullable=False)
    business_id = Column(String(255), nullable=False, index=True)
    project_path = Column(String(1024), nullable=False)
    provider = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="scheduled")
    findings_count = Column(Integer, nullable=False, default=0)
    report_json = Column(Text, nullable=True)
    report_file_path = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


business_id = Column(String(255), index=False)