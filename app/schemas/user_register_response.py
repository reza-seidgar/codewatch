"""Response schema for user registration (business_id, business_token only)"""
from pydantic import BaseModel

class UserRegisterResponse(BaseModel):
    business_id: str
    business_token: str
