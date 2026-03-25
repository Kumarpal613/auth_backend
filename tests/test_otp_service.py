import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
from datetime import datetime, timezone, timedelta

from app.services import otp_service
from app.core import security
from app.models.otps import OtpTracker, Otps
from app.models.user import User

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def mock_user():
    return User(id=1, email="test@example.com")

@pytest.fixture
def mock_tracker():
    tracker = OtpTracker()
    tracker.id = 1
    tracker.user_id = 1
    tracker.uuid = "fake-uuid"
    tracker.is_blocked = False
    tracker.attempts_count = 0
    tracker.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    tracker.last_edit_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    return tracker

def test_send_recovery_otp_success(mocker, mock_db, mock_user, mock_tracker):
    mocker.patch("app.services.otp_service.handle_recovery_tracker_lifecycle", return_value=mock_tracker)
    mocker.patch("app.services.otp_service.validate_blocked_tracker", return_value=True)
    mocker.patch("app.services.otp_service.check_otp_generation_permission", return_value=True)
    mocker.patch("app.services.otp_service.request_otp", return_value="123456")
    mocker.patch("app.services.otp_service.email.send_recovery_otp")
    mocker.patch("app.services.otp_service.create_recovery_token", return_value="fake_jwt")

    result = otp_service.send_recovery_otp(mock_db, mock_user)
    
    assert result["message"] == "Recovery OTP sent successfully"
    assert result["recovery_token"] == "fake_jwt"

def test_verify_recovery_otp_success(mocker, mock_db, mock_tracker):
    mocker.patch("app.services.otp_service.security.verify_jwt_token", return_value={"type": "recovery_session", "sub": "fake-uuid", "email": "test@example.com"})
    mocker.patch("app.services.otp_service.otp_repo.get_tracker_by_uuid", return_value=mock_tracker)
    
    mock_active_otp = Otps(otp="hashed_123456", is_used=False)
    mocker.patch("app.services.otp_service.otp_repo.get_active_otp_by_tracker_id", return_value=mock_active_otp)
    mocker.patch("app.services.otp_service.security.verify_otp", return_value=True)
    mocker.patch("app.services.otp_service.create_recovery_token", return_value="fake_reset_token")
    
    email, reset_token = otp_service.verify_recovery_otp(mock_db, "fake_token", "123456")
    
    assert email == "test@example.com"
    assert reset_token == "fake_reset_token"
    assert mock_active_otp.is_used is True

def test_verify_recovery_otp_invalid_token(mocker, mock_db):
    mocker.patch("app.services.otp_service.security.verify_jwt_token", return_value={"type": "wrong_type"})
    
    with pytest.raises(HTTPException) as exc:
        otp_service.verify_recovery_otp(mock_db, "bad_token", "123456")
        
    assert exc.value.status_code == 403
    assert "Invalid token type" in exc.value.detail

def test_verify_recovery_otp_wrong_otp(mocker, mock_db, mock_tracker):
    mocker.patch("app.services.otp_service.security.verify_jwt_token", return_value={"type": "recovery_session", "sub": "fake-uuid", "email": "test@example.com"})
    mocker.patch("app.services.otp_service.otp_repo.get_tracker_by_uuid", return_value=mock_tracker)
    
    mock_active_otp = Otps(otp="hashed_wrong", is_used=False)
    mocker.patch("app.services.otp_service.otp_repo.get_active_otp_by_tracker_id", return_value=mock_active_otp)
    mocker.patch("app.services.otp_service.security.verify_otp", return_value=False)
    
    with pytest.raises(HTTPException) as exc:
        otp_service.verify_recovery_otp(mock_db, "fake_token", "wrong_otp")
        
    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "Wrong OTP"

def test_handle_recovery_tracker_lifecycle_new_tracker(mocker, mock_db, mock_user):
    mocker.patch("app.services.otp_service.otp_repo.get_otp_tracker_by_user_id", return_value=None)
    mock_new_tracker = MagicMock()
    mocker.patch("app.services.otp_service.otp_repo.create_otp_tracker", return_value=mock_new_tracker)
    
    tracker = otp_service.handle_recovery_tracker_lifecycle(mock_db, mock_user)
    
    assert tracker == mock_new_tracker
    otp_service.otp_repo.create_otp_tracker.assert_called_once()
