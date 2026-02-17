from enum import Enum
from typing import Optional
from pydantic import BaseModel


class LLMProvider(str, Enum):
    LOCAL = "local"
    GAPGPT = "gapgpt"


class GapGPTModel(str, Enum):
    QWEN3_235B = "qwen3-235b-a22b"
    GPT4O_MINI = "gpt-4o-mini"
    GPT41_MINI = "gpt-4.1-mini"


class LLMConfig(BaseModel):
    provider: LLMProvider
    # فقط وقتی provider == GAPGPT پر میشه
    gapgpt_api_key: Optional[str] = None
    gapgpt_model: Optional[GapGPTModel] = None
    # فقط وقتی provider == LOCAL پر میشه
    local_base_url: Optional[str] = None   # مثال: http://87.236.166.36:8084
    local_model_name: Optional[str] = None # مثال: qwen3-30b-a3b-q4_k_m.gguf

    model_config = {"use_enum_values": True}
