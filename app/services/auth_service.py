from datetime import datetime, timedelta, timezone

from httpx import get
from app.models.user import User
from app.repositories.opt_repo import db_record_otp, db_record_password_recovery, db_update_password_recovery
from app.repositories.user_repo import get_user_by_email, get_user_by_id
from app.core.security import (
    generate_otp,
    hash_password,
    hash_refresh_token,
    create_refresh_token,
    create_access_token,
    hash_temp_password_token
)
from app.repositories.refresh_repo import (
    query_refresh_token,
    revoke_token,
    create_refresh_record
)

from fastapi import HTTPException, status
from app.core.config import settings
from app.utils.email import send_otp_email


def refresh_token_service(db, old_refresh: str):

    hashed = hash_refresh_token(old_refresh)

    db_token = query_refresh_token(db, hashed).first()

    if not db_token:
        raise HTTPException(401, "Invalid refresh token")

    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh expired")

    if db_token.revoked:
        raise HTTPException(401, "Refresh token revoked")

    # rotation
    revoke_token(db, db_token)

    return create_refresh_and_access_tokens(db, db_token.user_id)

def create_refresh_and_access_tokens(db, user_id: int):

    user = get_user_by_id(db,user_id)

    if not user:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    new_refresh = create_refresh_token()

    create_refresh_record(
        db=db,
        user_id=user.id,
        token_hash=hash_refresh_token(new_refresh),
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ) 

    access_token = create_access_token(user.id, user.token_version) 

    return access_token, new_refresh

def handle_password_recovery(db, user_id: int):
    db_record_password_recovery(db,user_id)

def deliver_otp_to_user(db, user_id:int , email: str):
    otp = generate_otp()
    otp_hash = hash_password(otp)

    try :
        db_record_otp(db, user_id, otp_hash)
        db_update_password_recovery(db,user_id, add_resend_counts=1, add_try_counts=1)
        send_otp_email(email, otp)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to record OTP") from e
