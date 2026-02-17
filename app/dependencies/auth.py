"""Authentication dependencies for FastAPI"""
from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional

from app.core.database import get_db
from app.core.security import verify_api_key
from app.models.user import User


async def verify_api_credentials(
    business_id: str = Header(..., alias="X-Business-Id"),
    business_token: str = Header(..., alias="X-Business-Token"),
    api_key: str = Header(..., alias="X-API-Key"),
    session: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency to verify API credentials from headers.
    Args:
        business_id: Business ID from X-Business-Id header
        business_token: Business token from X-Business-Token header
        api_key: API key from X-API-Key header
        session: Database session
    Returns:
        User: Authenticated user
    Raises:
        HTTPException: If credentials are invalid (401 Unauthorized)
    """
    stmt = select(User).where(
        User.business_id == business_id,
        User.business_token == business_token,
        User.is_active == True
    )
    result = await session.execute(stmt)
    user = result.scalars().first()
    from app.core.security import verify_api_key
    if user and verify_api_key(api_key, getattr(user, 'api_key')):
        return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
