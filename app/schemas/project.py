"""Pydantic schema for Project"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime


class ProjectResponse(BaseModel):
    id: str
    user_id: int
    project_path: str
    created_at: datetime

    # Pydantic v2 configuration for ORM conversion from SQLAlchemy objects
    model_config = ConfigDict(from_attributes=True)
