from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.user import User
from app.models.otps import Otps, OtpTracker
from app.core import security
from unittest.mock import patch
import logging

client = TestClient(app)

def clear_db(db):
    try:
        user = db.query(User).filter(User.email == "test_recovery@example.com").first()
        if user:
            db.query(OtpTracker).filter(OtpTracker.user_id == user.id).delete()
            db.query(User).filter(User.email == "test_recovery@example.com").delete()
        db.query(Otps).delete()
        db.commit()
    except Exception as e:
        print(f"Error clearing: {e}")
        db.rollback()

@patch('app.utils.email.send_recovery_otp')
@patch('app.core.security.generate_otp', return_value="123456")
def run_test(mock_gen_otp, mock_send_email):
    db = SessionLocal()
    clear_db(db)
    
    # 1. Create a user
    user = User(
        email="test_recovery@example.com",
        password=security.hash_password("old_password"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print("User created!")
    
    # 2. Request forgot password
    resp = client.post("/auth/password-recovery/request", json={"email": "test_recovery@example.com"})
    print("Request recovery:", resp.json())
    assert resp.status_code == 200
    recovery_token = resp.json().get("recovery_token")
    assert recovery_token
    
    # 3. Verify OTP
    print("Verifying OTP...")
    verify_resp = client.post(
        "/auth/password-recovery/verify",
        json={"otp": "123456"},
        headers={"Authorization": f"Bearer {recovery_token}"}
    )
    print("Verify Response:", verify_resp.json())
    assert verify_resp.status_code == 200
    reset_token = verify_resp.json().get("reset_token")
    assert reset_token
    
    # 4. Reset password
    print("Resetting password...")
    reset_resp = client.post(
        "/auth/password-recovery/reset",
        json={"new_password": "my_new_password_123", "token": reset_token}
    )
    print("Reset Response:", reset_resp.json())
    assert reset_resp.status_code == 200
    assert reset_resp.json() == {"message": "Password has been successfully updated."}
    
    # 5. Check if OTP Tracker is deleted
    assert db.query(OtpTracker).filter(OtpTracker.user_id == user.id).first() is None
    print("All OTP tables cleaned up properly!")
    
    db.close()

if __name__ == "__main__":
    run_test()
