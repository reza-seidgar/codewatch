"""Unified LLM client that wraps providers behind a single interface.

This file provides LLMClient which accepts an instance of LLMSetting (SQLAlchemy model)
and exposes `chat` and `health_check` methods. It also provides a factory
`get_llm_client(db, user_id)` that reads a user's LLMSetting from the database and
returns a configured LLMClient.

Note: This module depends on the `openai` package for AsyncOpenAI.
"""
from typing import Any
import asyncio

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
        timeout: float = 120.0,
    ) -> str:
        """
        ارسال پیام و دریافت پاسخ متنی
        """
        try:
            print(f"🔵 LLMClient.chat called:")
            print(f"   Model: {self._model}")
            print(f"   Temperature: {temperature}")
            print(f"   Max tokens: {max_tokens}")
            print(f"   Messages count: {len(messages)}")

            # ارسال درخواست
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                stream=False,  # مهم: غیرفعال کردن stream
            )

            # Debug: نوع و ساختار response
            print(f"🟢 Response received:")
            print(f"   Type: {type(response)}")

            # If provider returned a plain string (some SDKs do), accept it
            if isinstance(response, str):
                print("   Response is plain str")
                if not response.strip():
                    raise LLMError("Empty response from LLM (str)")
                print(f"✅ Returning content: {len(response)} chars")
                return response.strip()

            # If provider returned a dict-like object
            if isinstance(response, dict):
                choices = response.get("choices")
                print(f"   Has choices (dict): {choices is not None}")
                if not choices:
                    raise LLMError("Response has no choices (dict)")
                first = choices[0]
                # choice might be dict with message->content or text
                if isinstance(first, dict):
                    # message.content
                    msg = first.get("message") or first.get("delta")
                    if isinstance(msg, dict) and "content" in msg:
                        content = msg.get("content")
                        if content and str(content).strip():
                            print(f"✅ Returning content from dict: {len(content)} chars")
                            return str(content).strip()
                    # fallback to 'text'
                    if "text" in first and first["text"]:
                        content = first["text"]
                        if str(content).strip():
                            print(f"✅ Returning content from dict.text: {len(content)} chars")
                            return str(content).strip()
                    raise LLMError("Could not extract content from dict choice")

            # Otherwise try attribute-style extraction (SDK objects)
            has_choices = hasattr(response, "choices")
            print(f"   Has choices: {has_choices}")
            if not has_choices:
                raise LLMError(f"Response has no 'choices' attribute. Response type: {type(response)}")

            try:
                choices_len = len(response.choices)
            except Exception:
                choices_len = 0
            print(f"   Choices count: {choices_len}")
            if choices_len <= 0:
                raise LLMError("Response has empty choices list")

            choice = response.choices[0]
            print(f"   First choice type: {type(choice)}")

            # message may be attribute or key
            message = None
            if hasattr(choice, "message"):
                message = choice.message
            elif isinstance(choice, dict):
                message = choice.get("message") or choice.get("delta")

            print(f"   Has message: {message is not None}")
            if message is None:
                raise LLMError("Response choice has no 'message' attribute")

            # message.content may be attribute or key
            content = None
            if hasattr(message, "content"):
                content = message.content
            elif isinstance(message, dict):
                content = message.get("content") or message.get("text")

            print(f"   Has content: {content is not None}")
            if content is None:
                raise LLMError("Response message has no 'content' attribute")

            content_str = str(content)
            print(f"   Content type: {type(content)}")
            print(f"   Content is None: {content is None}")
            print(f"   Content length: {len(content_str) if content_str else 0}")
            preview = content_str[:200] if content_str else "NONE"
            print(f"   Content preview: {preview}")

            if not content_str.strip():
                raise LLMError(f"Response content is empty or whitespace only: {repr(content_str)}")

            print(f"✅ Returning content: {len(content_str)} chars")
            return content_str.strip()

        except LLMError:
            raise
        except Exception as e:
            print(f"❌ Unexpected error in LLMClient.chat:")
            print(f"   Error type: {type(e)}")
            print(f"   Error message: {str(e)}")
            import traceback

            traceback.print_exc()
            raise LLMError(f"LLM request failed: {type(e).__name__}: {str(e)}")

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
