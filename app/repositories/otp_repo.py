from datetime import datetime, timedelta, timezone
from hmac import new
from sqlalchemy.orm import Session
from pydantic import EmailStr
from app.core.config import settings
from app.models.otps import Otps, OtpTracker


def record_otp(db, tracker_id: int, otp: str):
    new_otp = Otps(
        tracker_id=tracker_id,
        otp=otp,
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes= settings.OTP_EXPIRE_MINUTES),
    )
    db.add(new_otp)
    db.flush()
    return new_otp

def deactivate_and_cleanup_otps(db: Session, tracker_id: int):
    db.query(Otps).filter(Otps.tracker_id == tracker_id).delete()
    db.flush()
    return True

def get_active_otp_by_tracker_id(db,tracker_id):
    now = datetime.now(timezone.utc)
    return db.query(Otps).filter(Otps.tracker_id == tracker_id , Otps.is_used == False,Otps.expires_at> now ).first()

def get_otp_tracker_by_temp_user_id(db, temp_user_id: int):
    return db.query(OtpTracker).filter(OtpTracker.user_id == temp_user_id, OtpTracker.is_temp == True).first()

def get_tracker_by_uuid(db, uuid ) -> OtpTracker:
    return db.query(OtpTracker).filter(OtpTracker.uuid == uuid).first()

def delete_otp_tracker_by_tracker_id(db, id: int):
    otp_tracker = db.query(OtpTracker).filter(OtpTracker.id == id).first()
    if otp_tracker:
        db.delete(otp_tracker)
        db.flush()
        return True
    return False

def create_otp_tracker(db, user_id: int, is_temp: bool = False, expires_hours: int = 24):
    now = datetime.now(timezone.utc)
    new_tracker = OtpTracker(
        user_id=user_id,
        is_temp=True,
        expires_at= now + timedelta(hours=expires_hours),
    )
    db.add(new_tracker)
    db.flush()
    return new_tracker

