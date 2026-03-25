import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from fastapi import HTTPException

from app.main import app
from app.db.session import get_db
from app.models.user import User

client = TestClient(app)

def override_get_db():
    yield MagicMock()

app.dependency_overrides[get_db] = override_get_db

def test_request_password_recovery_success(mocker):
    mock_user = User(id=1, email="test@example.com", password="hashed_password")
    mocker.patch("app.routers.auth.user_repo.get_user_by_email", return_value=mock_user)
    
    mocker.patch(
        "app.routers.auth.otp_service.send_recovery_otp", 
        return_value={"message": "Recovery OTP sent successfully", "recovery_token": "fake_token"}
    )
    
    response = client.post(
        "/auth/password-recovery/request",
        json={"email": "test@example.com"}
    )
    
    assert response.status_code == 200
    assert "recovery_token" in response.json()
    assert response.json()["recovery_token"] == "fake_token"

def test_request_password_recovery_user_not_found(mocker):
    mocker.patch("app.routers.auth.user_repo.get_user_by_email", return_value=None)
    
    response = client.post(
        "/auth/password-recovery/request",
        json={"email": "notfound@example.com"}
    )
    
    assert response.status_code == 200
    assert "If an account with that email exists" in response.json()["message"]
    assert "recovery_token" not in response.json()

def test_verify_recovery_otp_success(mocker):
    mocker.patch(
        "app.routers.auth.otp_service.verify_recovery_otp",
        return_value=("test@example.com", "fake_reset_token")
    )
    
    response = client.post(
        "/auth/password-recovery/verify",
        headers={"Authorization": "Bearer fake_recovery_token"},
        json={"otp": "123456"}
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["reset_token"] == "fake_reset_token"

def test_verify_recovery_otp_missing_token():
    response = client.post(
        "/auth/password-recovery/verify",
        json={"otp": "123456"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_resend_recovery_otp_success(mocker):
    mocker.patch(
        "app.routers.auth.otp_service.resend_recovery_otp",
        return_value={"message": "Recovery OTP sent successfully", "recovery_token": "new_fake_token"}
    )
    
    response = client.post(
        "/auth/password-recovery/resend",
        headers={"Authorization": "Bearer old_recovery_token"}
    )
    
    assert response.status_code == 200
    assert response.json()["recovery_token"] == "new_fake_token"

def test_reset_password_success(mocker):
    mocker.patch(
        "app.routers.auth.security.verify_jwt_token",
        return_value={"type": "reset_session", "email": "test@example.com", "sub": "fake-uuid"}
    )
    
    mock_user = User(id=1, email="test@example.com", password="hashed_password")
    mocker.patch("app.routers.auth.user_repo.get_user_by_email", return_value=mock_user)
    mocker.patch("app.routers.auth.security.hash_password", return_value="new_hashed")
    
    mock_tracker = MagicMock()
    mock_tracker.id = 1
    mocker.patch("app.routers.auth.otp_repo.get_tracker_by_uuid", return_value=mock_tracker)
    mocker.patch("app.routers.auth.otp_repo.delete_otp_tracker_by_tracker_id", return_value=True)

    response = client.post(
        "/auth/password-recovery/reset",
        json={"token": "fake_reset_token", "new_password": "new_strong_password"}
    )
    
    assert response.status_code == 200
    assert "Password has been successfully updated" in response.json()["message"]
    assert mock_user.password == "new_hashed"

def test_reset_password_invalid_token(mocker):
    def mock_verify(*args, **kwargs):
        raise HTTPException(status_code=403, detail="Invalid token type or expired")

    mocker.patch("app.routers.auth.security.verify_jwt_token", side_effect=mock_verify)
    
    response = client.post(
        "/auth/password-recovery/reset",
        json={"token": "expired_or_invalid", "new_password": "new_strong_password"}
    )
    
    assert response.status_code == 403
    assert "Invalid token type" in response.json()["detail"]
