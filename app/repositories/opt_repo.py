from datetime import datetime, timedelta, timezone
from hmac import new

from pydantic import EmailStr
from app.core.config import Settings
from app.models.otps import Otps, PasswordRecovery


def db_record_otp( db, user_id: int, otp: str):
    
    new_otp = Otps(user_id=user_id, otp=otp, expires_at= datetime.now(timezone.utc) +timedelta(minutes=Settings.otp_expire_minutes))

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

def db_record_password_recovery(db,user_id: int):
    
    new_recovery = PasswordRecovery(user_id=user_id)
    db.add(new_recovery)
    db.commit()

def db_get_password_recovery(db,user_id:int):
    recovery = db.query(PasswordRecovery).filter(
        PasswordRecovery.user_id == user_id
    ).first()

    return recovery

def db_update_password_recovery(db, user_id:int, add_resend_counts:int,add_try_counts:int,last_seen_at: datetime = datetime.now(timezone.utc)):
    recovery = db.query(PasswordRecovery).filter(
        PasswordRecovery.user_id == user_id
    ).update(
        {   
            PasswordRecovery.resend_count: PasswordRecovery.resend_count + add_resend_counts,
            PasswordRecovery.count_try: PasswordRecovery.count_try + add_try_counts,
            PasswordRecovery.last_seen_at: last_seen_at
        }
    )
    db.commit()

def db_delete_password_recovery(db,user_id:int):

    recovery = db.query(PasswordRecovery).filter(
        PasswordRecovery.user_id == user_id
    ).first()

    if recovery:
        db.delete(recovery)
        db.commit()
      