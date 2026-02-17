"""Tests for user endpoints"""
import pytest


@pytest.mark.asyncio
async def test_register_user_success(client):
    """Test successful user registration"""
    response = await client.post(
        "/api/v1/users/register",
        json={
            "business_id": "test-company-001",
            "business_name": "Test Company",
            "api_key": "test-api-key-123",
            "business_token": "test-token-456",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["business_id"] == "test-company-001"
    assert data["business_name"] == "Test Company"
    assert data["is_active"] is True
    assert "api_key" not in data
    assert "business_token" not in data


@pytest.mark.asyncio
async def test_register_user_duplicate_business_id(client):
    """Test user registration with duplicate business_id"""
    # Create first user
    await client.post(
        "/api/v1/users/register",
        json={
            "business_id": "test-company-001",
            "business_name": "Test Company",
            "api_key": "test-api-key-123",
            "business_token": "test-token-456",
        },
    )

    # Try to create duplicate
    response = await client.post(
        "/api/v1/users/register",
        json={
            "business_id": "test-company-001",
            "business_name": "Another Company",
            "api_key": "another-api-key",
            "business_token": "another-token",
        },
    )

    assert response.status_code == 409
