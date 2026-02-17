"""Pydantic schemas for User-related requests and responses"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class UserCreate(BaseModel):
    """
    Schema for creating a new user.
    
    Attributes:
        business_id: Unique identifier for the business
        business_name: Name of the business
        api_key: API key for authentication
        business_token: Token for internal authentication
    """

    business_id: str = Field(..., min_length=1, max_length=255, description="Business ID")
    business_name: str = Field(..., min_length=1, max_length=255, description="Business name")
    api_key: str = Field(..., min_length=1, description="API key for authentication")
    business_token: str = Field(..., min_length=1, description="Business token for authentication")


class UserResponse(BaseModel):
    """
    Schema for user response.
    
    Attributes:
        id: User ID
        business_id: Unique identifier for the business
        business_name: Name of the business
        is_active: Whether the user is active
        created_at: Timestamp of user creation
    
    Note:
        api_key and business_token are NOT included in response
    """

    id: int
    business_id: str
    business_name: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserAuth(BaseModel):
    """
    Schema for user authentication credentials.
    
    Attributes:
        api_key: API key for authentication
        business_token: Token for internal authentication
    """

    api_key: str = Field(..., description="API key for authentication")
    business_token: str = Field(..., description="Business token for authentication")
