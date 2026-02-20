from email.policy import HTTP
import re
from tabnanny import check
from fastapi import HTTPException, status
from app.core.config import settings
from app.core import security
from app.models.otps import OtpTracker
from app.models.user import TempUser
from app.repositories import otp_repo, user_repo
from app.schemas.opts import TrackerState
from app.utils import email
from datetime import datetime, timedelta, timezone

def is_tracker_expired(tracker: OtpTracker) -> bool:
    return datetime.now(timezone.utc) > tracker.expires_at

def handle_tracker_lifecycle(db, temp_user: TempUser) -> OtpTracker:
    tracker = otp_repo.get_otp_tracker_by_temp_user_id(db, temp_user.id)
    now = datetime.now(timezone.utc)
    if tracker and  tracker.expires_at < now + timedelta(minutes=settings.OTP_EXPIRE_MINUTES) :
        otp_repo.delete_otp_tracker_by_tracker_id(db, id=tracker.id)
        tracker = None

    if tracker is None:
        tracker = otp_repo.create_otp_tracker(db, user_id=temp_user.id, is_temp=True,expires_hours = settings.OTP_TRACKER_EXPIRE_HOURS)

    return tracker

def request_otp(db, tracker: OtpTracker):
    now = datetime.now(timezone.utc)

    if tracker.attempts_count + 1 > settings.MAX_OTP_ATTEMPTS:
        tracker.is_blocked = True
        tracker.blocked_until = now + timedelta(
            minutes=settings.OTP_TRACKER_LOCK_MINUTES
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Your Account is Temporarily blocked. Please check your email to unblock.",
                "retry after": int(settings.OTP_TRACKER_LOCK_MINUTES*60),
            } ,
        )
    
    otp_repo.deactivate_and_cleanup_otps(db,tracker_id=tracker.id)

    otp = security.generate_otp()
    hashed_otp = security.hash_otp(otp)
    otp_repo.record_otp(db=db, tracker_id=tracker.id, otp=hashed_otp)

    tracker.attempts_count += 1
    tracker.last_edit_at = now
    db.flush()

    return otp

def check_otp_generation_permission(db, tracker: OtpTracker):
    now = datetime.now(timezone.utc)

    if tracker.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "OTP Tracker expired.", "retry_after": 0},
        )   
    
    if tracker.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "message": "Your Account is Temporarily blocked.",
                "retry_after": int((tracker.blocked_until - now).total_seconds()),
            },
        )

    elapsed_since_update = (now - tracker.last_edit_at).total_seconds()
    
    cooldown = settings.RESEND_COOLDOWN_SECONDS - elapsed_since_update 

    if tracker.attempts_count!= 0 and cooldown > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Too many resend request.Please wait for cooldown before try again.",
                "retry_after": cooldown,
            },
        )

    return True

def validate_blocked_tracker(db,tracker):
    now = datetime.now(timezone.utc)

    if tracker.is_blocked :
        cooldown = (tracker.blocked_until - now).total_seconds()
        if  cooldown <= 0 :
            tracker.is_blocked = False
            tracker.blocked_until = None
            
        else :
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail ={"message":"Maximum OTP limit reached. Please wait for cooldown before try again","retry_after":int(cooldown)} )
        
    db.flush()
    return True

def create_signup_token(
    tracker_uuid: str,
    email: str,
    valid_till_minutes: int = settings.SIGNUP_TOKEN_EXPIRE_MINUTES,
):

    expire = datetime.now(timezone.utc) + timedelta(minutes=valid_till_minutes)
    payload = {
        "sub": str(tracker_uuid),  # The unique public identifier
        "type": "signup_session",  # Limits what this token can do
        "email": email,
        "exp": expire,
    }

    jwt_token = security.create_jwt_token(payload=payload)
    return jwt_token

def send_signup_otp(db, temp_user: TempUser):

    tracker = handle_tracker_lifecycle(db, temp_user=temp_user)

    validate_blocked_tracker(db,tracker)
    check_otp_generation_permission(db, tracker)
    otp = request_otp(db, tracker)
    print("this is the otp: ",otp)
    email.send_signup_otp(temp_user.email, otp)
    jwt_token = create_signup_token(str(tracker.uuid),temp_user.email)

    return {"message": "OTP sent successfully","signup_token": jwt_token}

def resend_signup_otp(db, token ):

    payload = security.verify_jwt_token(token)
    if payload.get("type") != "signup_session":
        raise HTTPException(status_code=403, detail="Invalid token type")
    tracker_uuid = payload.get("sub")
    tracker = otp_repo.get_tracker_by_uuid(db, uuid = tracker_uuid)
    if tracker is None :
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Registration session not found. Please start signup again."
        )
    
    validate_blocked_tracker(db,tracker)
    check_otp_generation_permission(db, tracker)
    otp = request_otp(db, tracker)
    temp_user = user_repo.get_temp_user_by_email(db,payload["email"])
    if temp_user is None :
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail={"message":"User Not Found"})
    print("this is the otp: ",otp)
    email.send_signup_otp(temp_user.email, otp)
    jwt_token = create_signup_token(str(tracker.uuid),temp_user.email)

    return {"message": "OTP sent successfully","signup_token": jwt_token}

def verify_signup_otp(db,token, otp):
    payload = security.verify_jwt_token(token)
    
    if not payload or payload.get("type") != "signup_session":
        raise HTTPException(status_code=403, detail="Invalid token type or expired")
    tracker_uuid = payload.get("sub")
    tracker = otp_repo.get_tracker_by_uuid(db, uuid = tracker_uuid)

    if tracker is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail={"message": "Signup session not found. Please resend OTP."}
        )
    
    db_otp = otp_repo.get_active_otp_by_tracker_id(db,tracker.id)
    if db_otp is None :
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail={"message":"Otp is not requested"})
  
    verified =  security.verify_otp(otp,otp_hash=db_otp.otp) 
    
    if verified :
        db_otp.is_used = True
        db.flush()
    else :
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail={"message":"Wrong OTP"})

    return payload["email"] 





if __name__ == "__main__":

    from app.db.session import engine
    from app.db.base import Base
    from app.db.session import SessionLocal
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    tracker = OtpTracker(
        user_id=2,
        is_temp=True,
        is_blocked = True,
        blocked_until = now,
        attempts_count=1,
        expires_at= now + timedelta(hours=settings.OTP_TRACKER_EXPIRE_HOURS),
        last_edit_at = now-timedelta(seconds=31),
    )
    db.add(tracker)
    db.flush()
    temp_user = TempUser( id = 2,email="palkumar@gmail.com",password="123")
    db.add(temp_user)
    db.flush()
    try:
        # print("---Testing Otp Permision---")
        # allowed = check_otp_generation_permission(db, tracker)
        # print(allowed)

        # print("--Testing Otp Validate blocker tracker--")
        # valid = validate_blocked_tracker(db,tracker)
        # print(valid)

        # print("--Test handle tracker lifecycle--")
        # tracker = handle_tracker_lifecycle(db,temp_user)
        # print(tracker.user_id)

        # print("--Test request_otp--")
        # otp = request_otp(db,tracker)
        # print(otp)
        
        # print("--Testing send signup otp--")
        # token = send_signup_otp(db,temp_user)["signup_token"]
        # print("Token",token)
        # print("--send signup otp complete--")

        # token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmNzE1MzBlMS1iODU3LTQwNDctOTU4YS1jNDU4YmM0MDY2YjAiLCJ0eXBlIjoic2lnbnVwX3Nlc3Npb24iLCJlbWFpbCI6InBhbGt1bWFyQGdtYWlsLmNvbSIsImV4cCI6MTc3MTUxMTQzNH0.Hdvab8qJU5iOlsL527kcSa0GJWuvLHKTbZ2u7JWUxss"
        # print("--Testing resend signup otp--")
        # resend_signup_otp(db,token)
        # print("--resend signup otp complete--")

        pass

    finally:
        db.close()
