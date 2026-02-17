"""Application configuration using Pydantic Settings"""
from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # App Configuration
    APP_NAME: str = "CodeWatch"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Database Configuration
    DATABASE_URL: str = "sqlite+aiosqlite:///./codewatch.db"

    # Security Configuration
    SECRET_KEY: str = "change-this-to-a-random-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()
