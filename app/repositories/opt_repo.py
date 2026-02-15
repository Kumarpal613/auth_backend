from datetime import datetime, timedelta, timezone
from hmac import new

from pydantic import EmailStr
from app.core.config import Settings
from app.models.otps import Otps, OtpTracker


def db_record_otp( db, tracker_id: int, otp: str):
    
    new_otp = Otps(tracker_id=tracker_id, otp=otp, expires_at= datetime.now(timezone.utc) +timedelta(minutes=Settings.otp_expire_minutes))

    db.add(new_otp)
    db.commit()
    
def db_verify_otp( db,user_id: int, otp: str,) -> bool:
    db_otp = db.query(Otps).filter(
        Otps.user_id == user_id,
        Otps.otp == otp,
        Otps.is_used == False,
        Otps.expires_at > datetime.now(timezone.utc)
    ).first()

    if not db_otp:
        return False
    db.delete(db_otp)
    db.commit()
    return True

def db_invalidate_otp(user_id: int, db):
    # Invalidate existing OTPs
    old_opt = db.query(Otps).filter(
        Otps.user_id == user_id,
        Otps.is_used == False,
    ).first()

    if old_opt is None:
        raise ValueError("No active OTP found for this user_id")
    
    db.delete(old_opt)
    db.commit()

def db_record_otp_tracker(db,user_id: int, is_temp: bool):
    new_tracker = OtpTracker(user_id=user_id, is_temp=is_temp)
    db.add(new_tracker)
    db.commit()