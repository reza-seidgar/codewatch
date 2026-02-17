"""Endpoints to manage per-user LLM settings"""
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import verify_api_credentials
from app.core.database import get_db
from app.schemas.llm_setting import LLMSettingCreate, LLMSettingResponse
from app.services.llm_service import get_user_llm_setting, upsert_llm_setting
from app.models.user import User

router = APIRouter(prefix="/llm")


POST_DESCRIPTION = (
    "Create or update (upsert) LLM settings for the authenticated user.\n\n"
    "Provider-specific requirements:\n"
    "- **local**: set `local_base_url` and `local_model_name`. Example:\n"
    "```json\n{\n  \"provider\": \"local\",\n  \"local_base_url\": \"http://127.0.0.1:8084\",\n  \"local_model_name\": \"qwen3-30b-a3b-q4_k_m.gguf\"\n}\n```\n"
    "- **gapgpt**: set `gapgpt_api_key` and `gapgpt_model`. Example:\n"
    "```json\n{\n  \"provider\": \"gapgpt\",\n  \"gapgpt_api_key\": \"sk-gapgpt-...\",\n  \"gapgpt_model\": \"qwen3-235b-a22b\"\n}\n```\n"
    "Notes:\n"
    "- `gapgpt_api_key` is never returned in responses.\n"
    "- Use the `GET /api/v1/llm/settings` endpoint to retrieve the current settings.\n"
)


@router.post(
    "/settings",
    response_model=LLMSettingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update LLM settings",
    description=POST_DESCRIPTION,
)
async def create_or_update_llm_setting(
    data: LLMSettingCreate,
    authenticated_user: User = Depends(verify_api_credentials),
    db: AsyncSession = Depends(get_db),
) -> LLMSettingResponse:
    """Create or update (upsert) LLM settings for the authenticated user."""
    setting = await upsert_llm_setting(db, authenticated_user.id, data)
    return LLMSettingResponse.model_validate(setting)


GET_DESCRIPTION = (
    "Return the LLM settings for the authenticated user.\n\n"
    "If no settings exist, the endpoint returns a 404.\n"
    "The response **does not** include sensitive fields such as `gapgpt_api_key`.\n"
)


@router.get(
    "/settings",
    response_model=LLMSettingResponse,
    summary="Get user LLM settings",
    description=GET_DESCRIPTION,
)
async def get_llm_setting(
    authenticated_user: User = Depends(verify_api_credentials),
    db: AsyncSession = Depends(get_db),
) -> LLMSettingResponse:
    """Get LLM settings for the authenticated user."""
    setting = await get_user_llm_setting(db, authenticated_user.id)
    if not setting:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="LLM setting not found")
    return LLMSettingResponse.model_validate(setting)
