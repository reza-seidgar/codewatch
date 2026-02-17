"""Security utilities for API key hashing and token generation"""

import secrets
import hashlib
import hmac
from typing import Optional
from datetime import datetime, timedelta, UTC
from passlib.context import CryptContext
from app.core.config import settings

# Password context for bcrypt hashing (for user passwords only)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- API Key Hashing (SHA-256 or HMAC-SHA256) ---
def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using SHA-256 or HMAC-SHA256 (if SECRET_KEY is set).
    Args:
        api_key: The plain text API key to hash
    Returns:
        str: The hex digest of the hashed API key
    """
    secret = getattr(settings, "SECRET_KEY", None)
    if secret:
        return hmac.new(secret.encode(), api_key.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(plain_api_key: str, hashed_api_key: str) -> bool:
    """
    Verify a plain API key against its SHA-256 (or HMAC-SHA256) hash.
    Args:
        plain_api_key: The plain text API key
        hashed_api_key: The hash from database
    Returns:
        bool: True if API key is valid, False otherwise
    """
    return hash_api_key(plain_api_key) == hashed_api_key

# --- Password Hashing (bcrypt, for user passwords only) ---
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_business_token() -> str:
    """
    Generate a secure random business token.
    Returns:
        str: A secure random token (32 bytes hex encoded)
    """
    return secrets.token_hex(32)

def generate_scan_id() -> str:
    """
    Generate a unique scan ID.
    Returns:
        str: A unique scan ID (UUID-like format using secrets)
    """
    return secrets.token_hex(16)
