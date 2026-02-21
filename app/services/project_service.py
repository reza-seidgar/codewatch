"""Project service for managing user projects"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from uuid import uuid4
from fastapi import HTTPException, status

from app.models.project import Project
from app.models.user import User
from app.schemas.project import ProjectResponse

class ProjectService:
    @staticmethod
    async def create_project(session: AsyncSession, user: User, project_path: str) -> ProjectResponse:
        # generate a random UUID string for the project id so callers can safely reference it
        new_project = Project(id=str(uuid4()), user_id=user.id, project_path=project_path)
        session.add(new_project)
        try:
            await session.commit()
            await session.refresh(new_project)
            return ProjectResponse.model_validate(new_project)
        except IntegrityError as e:
            await session.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project already exists.") from e

    @staticmethod
    async def get_projects_for_user(session: AsyncSession, user: User):
        stmt = select(Project).where(Project.user_id == user.id)
        result = await session.execute(stmt)
        return result.scalars().all()
