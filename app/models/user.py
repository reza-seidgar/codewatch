"""User SQLAlchemy model"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

from app.core.database import Base


class User(Base):
    """
    User model representing a business/organization using CodeWatch.
    
    Attributes:
        id: Primary key, auto-incrementing integer
        business_id: Unique identifier for the business
        business_name: Name of the business
        api_key: Hashed API key for authentication
        business_token: Token for internal authentication
        is_active: Whether the user/business is active
        created_at: Timestamp of user creation
        updated_at: Timestamp of last update
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    business_id = Column(String(255), unique=True, nullable=False, index=True)
    business_name = Column(String(255), nullable=False)
    api_key = Column(String(255), nullable=False)
    business_token = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationship: one user has many projects
    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    # One-to-one relationship to LLMSetting
    llm_setting = relationship("LLMSetting", back_populates="user", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, business_id={self.business_id}, business_name={self.business_name})>"
