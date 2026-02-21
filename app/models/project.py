"""Project SQLAlchemy model"""
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

from app.core.database import Base

class Project(Base):
    """
    Project model representing a code project for scanning.
    Attributes:
        id: Primary key
        user_id: Foreign key to User
        project_path: Path to the project
        created_at: Timestamp
    """
    __tablename__ = "projects"

    # Use a string UUID for project id to avoid leaking sequential ids and to match SAST reports
    id = Column(String(36), primary_key=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    project_path = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="projects")
