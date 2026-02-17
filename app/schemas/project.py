"""Pydantic schema for Project"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class ProjectResponse(BaseModel):
    id: int
    user_id: int
    project_path: str
    created_at: datetime

    class Config:
        from_attributes = True
