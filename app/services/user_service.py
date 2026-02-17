"""User service for business logic"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status

from app.models.user import User
from app.schemas.user import UserCreate, UserResponse
from app.core.security import hash_api_key


class UserService:
    @staticmethod
    async def create_user_with_ids(session: AsyncSession, api_key: str, business_id: str, business_token: str) -> None:
        """
        Create a new user only if api_key matches the allowed value.
        """
        ALLOWED_API_KEY = "gIRPur8mixXtKB0kN36VqBqLidWJXmuD"
        from app.core.security import hash_api_key
        from app.models.user import User
        from sqlalchemy.exc import IntegrityError
        from fastapi import HTTPException, status

        if api_key != ALLOWED_API_KEY:
            # Do not register user if api_key is not allowed
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key for registration.")

        hashed_api_key = hash_api_key(api_key)
        new_user = User(
            business_id=business_id,
            business_name=business_id,  # No business_name in this flow
            api_key=hashed_api_key,
            business_token=business_token,
            is_active=True,
        )
        session.add(new_user)
        await session.commit()
    """Service for user-related operations"""

    @staticmethod
    async def create_user(session: AsyncSession, user_data: UserCreate) -> UserResponse:
        """
        Create a new user.
        
        Args:
            session: Database session
            user_data: User creation data
            
        Returns:
            UserResponse: Created user data
            
        Raises:
            HTTPException: If business_id already exists (409 Conflict)
        """
        # Hash the API key before storing
        hashed_api_key = hash_api_key(user_data.api_key)

        # Create new user instance
        new_user = User(
            business_id=user_data.business_id,
            business_name=user_data.business_name,
            api_key=hashed_api_key,
            business_token=user_data.business_token,
            is_active=True,
        )

        try:
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return UserResponse.model_validate(new_user)
        except IntegrityError as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Business ID already exists",
            ) from e

    @staticmethod
    async def get_user_by_business_id(
        session: AsyncSession, business_id: str
    ) -> User | None:
        """
        Get user by business_id.
        
        Args:
            session: Database session
            business_id: Business ID
            
        Returns:
            User: User object if found, None otherwise
        """
        stmt = select(User).where(User.business_id == business_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    @staticmethod
    async def get_user_by_api_key(session: AsyncSession, api_key: str) -> User | None:
        """
        Get user by API key (note: api_key is hashed in database).
        This is a helper that doesn't verify - actual verification happens in auth.
        
        Args:
            session: Database session
            api_key: API key (plain text)
            
        Returns:
            User: User object if found, None otherwise
        """
        # Since API keys are hashed, we can't query directly
        # This method would require additional logic or a separate lookup table
        # For now, returning None - verification happens via dependency
        return None
