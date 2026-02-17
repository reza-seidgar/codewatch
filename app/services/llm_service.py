"""Service for managing per-user LLM settings (CRUD operations only)."""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status

from app.models.llm_setting import LLMSetting
from app.schemas.llm_setting import LLMSettingCreate


async def get_user_llm_setting(db: AsyncSession, user_id: int) -> Optional[LLMSetting]:
    """Return the LLMSetting for a given user_id, or None if not found."""
    stmt = select(LLMSetting).where(LLMSetting.user_id == user_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def upsert_llm_setting(db: AsyncSession, user_id: int, data: LLMSettingCreate) -> LLMSetting:
    """Create or update the LLMSetting for a user.

    If a setting exists for the user, update it. Otherwise insert a new row.
    Returns the LLMSetting SQLAlchemy instance.
    """
    existing = await get_user_llm_setting(db, user_id)

    # Normalize provider to string
    provider_value = data.provider.value if hasattr(data.provider, "value") else str(data.provider)

    if existing:
        # Update fields according to provider
        existing.provider = provider_value
        if provider_value == "gapgpt":
            existing.gapgpt_api_key = data.gapgpt_api_key
            existing.gapgpt_model = data.gapgpt_model.value if hasattr(data.gapgpt_model, "value") else data.gapgpt_model
            existing.local_base_url = None
            existing.local_model_name = None
        else:
            existing.local_base_url = data.local_base_url
            existing.local_model_name = data.local_model_name
            existing.gapgpt_api_key = None
            existing.gapgpt_model = None

        try:
            db.add(existing)
            await db.commit()
            await db.refresh(existing)
            return existing
        except IntegrityError as e:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update LLM setting") from e
    else:
        # Insert new setting
        new = LLMSetting(
            user_id=user_id,
            provider=provider_value,
            gapgpt_api_key=data.gapgpt_api_key if provider_value == "gapgpt" else None,
            gapgpt_model=(data.gapgpt_model.value if hasattr(data.gapgpt_model, "value") else data.gapgpt_model) if provider_value == "gapgpt" else None,
            local_base_url=data.local_base_url if provider_value == "local" else None,
            local_model_name=data.local_model_name if provider_value == "local" else None,
        )
        try:
            db.add(new)
            await db.commit()
            await db.refresh(new)
            return new
        except IntegrityError as e:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to create LLM setting") from e
