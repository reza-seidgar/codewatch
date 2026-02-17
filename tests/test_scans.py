"""Tests for scan endpoints"""
import pytest


@pytest.mark.asyncio
async def test_submit_scan_success(client):
    """Test successful scan submission"""
    # First register a user
    user_response = await client.post(
        "/api/v1/users/register",
        json={
            "business_id": "test-company-001",
            "business_name": "Test Company",
            "api_key": "test-api-key-123",
            "business_token": "test-token-456",
        },
    )

    assert user_response.status_code == 201

    # Submit a scan with credentials
    scan_response = await client.post(
        "/api/v1/scans/submit",
        json={
            "project_path": "/home/ubuntu/my-project",
            "scan_mode": "quick",
        },
        headers={
            "X-API-Key": "test-api-key-123",
            "X-Business-Token": "test-token-456",
        },
    )

    assert scan_response.status_code == 202
    data = scan_response.json()
    assert "scan_id" in data
    assert data["status"] == "queued"
    assert data["project_path"] == "/home/ubuntu/my-project"


@pytest.mark.asyncio
async def test_submit_scan_invalid_credentials(client):
    """Test scan submission with invalid credentials"""
    response = await client.post(
        "/api/v1/scans/submit",
        json={
            "project_path": "/home/ubuntu/my-project",
            "scan_mode": "quick",
        },
        headers={
            "X-API-Key": "invalid-key",
            "X-Business-Token": "invalid-token",
        },
    )

    assert response.status_code == 401
