from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session
from app.models.otps import OtpTracker
from app.models.user import TempUser, User
from app.repositories import otp_repo
from app.repositories import user_repo
from app.core import security
from app.repositories import refresh_repo

from fastapi import HTTPException, status
from app.core.config import settings
from app.utils import email
from app.schemas import auth

def create_refresh_and_access_tokens(db, user_id: int):

    user = user_repo.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")

    new_refresh = security.create_refresh_token()

    refresh_repo.create_refresh_record(
        db=db,
        user_id=user.id,
        token_hash= security.hash_refresh_token(new_refresh),
        token_version=user.token_version,
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )

    access_token = security.create_access_token(user.id, user.token_version)

    return access_token, new_refresh

def verify_refresh_token_and_revoke(db:Session,refresh_token)->User:
    token_hash = security.hash_refresh_token(refresh_token)

    refresh_token = refresh_repo.get_refresh_token(db, token_hash)
    
    if refresh_token is None :
        raise HTTPException(401, "Invalid refresh token")

    if refresh_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh expired")

    if refresh_token.revoked:
        raise HTTPException(401, "Refresh token revoked")

    user = user_repo.get_user_by_id(db, refresh_token.user_id)
    if not user or user.token_version != refresh_token.token_version:
        raise HTTPException(401, "Invalid or expired session. Please log in again.")
    
    refresh_token.revoked = True
    db.flush()

    return user

def create_temp_user(db, user_data: auth.SignupReq):
    user_data.password = security.hash_password(user_data.password)
    temp_user = user_repo.create_temp_user(db, user_data)
    db.flush()
    return temp_user

def register_permanent_user(db, temp_user_email: str)->User :
    temp_user = user_repo.get_temp_user_by_email(db,temp_user_email)
    user = user_repo.create_user(db,temp_user)
    if  user is None :
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail={"message":"Creation of User Account, failed"})
    return user 
 
