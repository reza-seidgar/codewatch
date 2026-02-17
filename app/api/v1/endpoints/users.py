"""User management endpoints"""
from fastapi import APIRouter, Depends, status, Path
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.user_service import UserService
from app.schemas.user_register_response import UserRegisterResponse

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/register/{api_key}", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    api_key: str = Path(..., description="API key for registration"),
    session: AsyncSession = Depends(get_db),
) -> UserRegisterResponse:
    """
    Register a new user with only api_key as path parameter.
    Returns random business_id and business_token.
    """
    from app.core.security import generate_business_token
    import secrets
    import string

    # Generate random business_id (e.g. 12-char alphanumeric)
    business_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    business_token = generate_business_token()
    await UserService.create_user_with_ids(session, api_key, business_id, business_token)
    return UserRegisterResponse(business_id=business_id, business_token=business_token)
