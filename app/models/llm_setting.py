"""LLMSetting SQLAlchemy model"""
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class LLMSetting(Base):
    """
    LLMSetting model stores per-user LLM configuration.

    Fields:
    - id: int primary key
    - user_id: int foreign key to users.id (unique=True)
    - provider: str ("local" or "gapgpt")
    - gapgpt_api_key: str nullable
    - gapgpt_model: str nullable
    - local_base_url: str nullable
    - local_model_name: str nullable
    - created_at: datetime
    - updated_at: datetime (onupdate)
    """

    __tablename__ = "llm_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    provider = Column(String(64), nullable=False)

    gapgpt_api_key = Column(String(512), nullable=True)
    gapgpt_model = Column(String(128), nullable=True)
    local_base_url = Column(String(512), nullable=True)
    local_model_name = Column(String(256), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationship back to user (one-to-one)
    user = relationship("User", back_populates="llm_setting")
