"""Pydantic schemas for LLMSetting"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, model_validator

from app.core.llm_config import LLMProvider, GapGPTModel


class LLMSettingCreate(BaseModel):
    """Schema for creating LLM settings.

    Validation rules (after validation):
    - If provider == GAPGPT: gapgpt_api_key and gapgpt_model are required.
    - If provider == LOCAL: local_base_url and local_model_name are required.
    """

    provider: LLMProvider = Field(
        ...,
        description="LLM provider to use. Allowed values: 'local' or 'gapgpt'.",
    )

    # GAPGPT fields
    gapgpt_api_key: Optional[str] = Field(
        default=None,
        description="API key for GapGPT (required when provider == 'gapgpt').",
        example="sk-gapgpt-...",
    )
    gapgpt_model: Optional[GapGPTModel] = Field(
        default=None,
        description="GapGPT model to use (required when provider == 'gapgpt').",
    )

    # LOCAL fields
    local_base_url: Optional[str] = Field(
        default=None,
        description="Base URL for a local LLM server (required when provider == 'local').",
        example="http://127.0.0.1:8084",
    )
    local_model_name: Optional[str] = Field(
        default=None,
        description="Model name or path for a local LLM (required when provider == 'local').",
        example="qwen3-30b-a3b-q4_k_m.gguf",
    )

    model_config = {
        "use_enum_values": True,
        "json_schema_extra": {
            "examples": [
                {
                    "summary": "Local provider example",
                    "value": {
                        "provider": "local",
                        "local_base_url": "http://127.0.0.1:8084",
                        "local_model_name": "qwen3-30b-a3b-q4_k_m.gguf"
                    }
                },
                {
                    "summary": "GapGPT provider example",
                    "value": {
                        "provider": "gapgpt",
                        "gapgpt_api_key": "sk-gapgpt-...",
                        "gapgpt_model": "qwen3-235b-a22b"
                    }
                }
            ]
        },
    }

    @model_validator(mode="after")
    def check_provider_fields(self) -> "LLMSettingCreate":
        if self.provider == LLMProvider.GAPGPT:
            if not self.gapgpt_api_key or not self.gapgpt_model:
                raise ValueError("gapgpt_api_key and gapgpt_model are required when provider is 'gapgpt'.")
        elif self.provider == LLMProvider.LOCAL:
            if not self.local_base_url or not self.local_model_name:
                raise ValueError("local_base_url and local_model_name are required when provider is 'local'.")
        return self


class LLMSettingResponse(BaseModel):
    """Response schema for LLM settings. Note: gapgpt_api_key is never returned."""

    id: int
    provider: LLMProvider
    gapgpt_model: Optional[GapGPTModel] = None
    local_base_url: Optional[str] = None
    local_model_name: Optional[str] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True, "use_enum_values": True}


class LLMSettingUpdate(BaseModel):
    """Schema for partial update of LLM settings. All fields optional."""

    provider: Optional[LLMProvider] = None
    gapgpt_api_key: Optional[str] = None
    gapgpt_model: Optional[GapGPTModel] = None
    local_base_url: Optional[str] = None
    local_model_name: Optional[str] = None

    model_config = {"use_enum_values": True}
