"""Unified LLM client that wraps providers behind a single interface.

This file provides LLMClient which accepts an instance of LLMSetting (SQLAlchemy model)
and exposes `chat` and `health_check` methods. It also provides a factory
`get_llm_client(db, user_id)` that reads a user's LLMSetting from the database and
returns a configured LLMClient.

Note: This module depends on the `openai` package for AsyncOpenAI.
"""
from typing import Any

from openai import AsyncOpenAI
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.llm_setting import LLMSetting


class LLMError(Exception):
    """Custom exception for LLM client errors."""


class LLMClient:
    def __init__(self, setting: LLMSetting):
        self._setting = setting
        provider = getattr(setting, "provider")
        # provider stored as string in DB
        if provider == "gapgpt":
            self._client = AsyncOpenAI(
                base_url="https://api.gapgpt.app/v1",
                api_key=getattr(setting, "gapgpt_api_key"),
            )
            self._model = getattr(setting, "gapgpt_model")
        else:  # local
            base = getattr(setting, "local_base_url") or ""
            self._client = AsyncOpenAI(
                base_url=f"{base}/v1" if base else "",
                api_key="not-needed",
            )
            self._model = getattr(setting, "local_model_name")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """Send messages to the configured LLM and return a text response.

        Raises LLMError on failure.
        """
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            # Support for response.choices[0].message.content
            choices = getattr(response, "choices", None)
            if choices:
                message = choices[0].message
                content = getattr(message, "content", None)
                if content is not None:
                    return content
            # Fallbacks
            text = getattr(response, "text", None)
            if text:
                return text
            raise LLMError("Empty response from LLM")
        except Exception as exc:
            raise LLMError(str(exc)) from exc

    async def health_check(self) -> bool:
        """Simple health check: ask the model to reply 'ok' and return True if we get any response."""
        try:
            result = await self.chat(messages=[{"role": "user", "content": "reply with: ok"}], max_tokens=5)
            return bool(result)
        except Exception:
            return False


async def get_llm_client(db: AsyncSession, user_id: int) -> LLMClient:
    """Factory: read user's LLMSetting from the DB and return an LLMClient.

    Raises:
        ValueError: if the user has no LLMSetting configured.
    """
    stmt = select(LLMSetting).where(LLMSetting.user_id == user_id)
    result = await db.execute(stmt)
    setting = result.scalars().first()
    if not setting:
        raise ValueError("No LLMSetting configured for user")
    return LLMClient(setting)
