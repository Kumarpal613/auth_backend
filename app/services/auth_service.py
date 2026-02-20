from datetime import datetime, timedelta, timezone

from httpx import get
from app.models.otps import OtpTracker
from app.models.user import TempUser, User
from app.repositories import otp_repo
from app.repositories.user_repo import (
    create_temp_user,
    get_user_by_email,
    get_user_by_id,
)
from app.repositories import user_repo
from app.core import security
from app.core import security
from app.repositories import refresh_repo

from fastapi import HTTPException, status
from app.core.config import settings
from app.utils import email
from app.schemas import auth


def refresh_token_service(db, old_refresh: str):

    hashed = security.hash_refresh_token(old_refresh)

    db_token = refresh_repo.query_refresh_token(db, hashed).first()

    if not db_token:
        raise HTTPException(401, "Invalid refresh token")

    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh expired")

    if db_token.revoked:
        raise HTTPException(401, "Refresh token revoked")

    # rotation
    refresh_repo.revoke_token(db, db_token)

    user = get_user_by_id(db, db_token.user_id)
    if user.token_version != db_token.token_version:
        raise HTTPException(401, "Token version mismatch")

    return create_refresh_and_access_tokens(db, db_token.user_id)

def create_refresh_and_access_tokens(db, user_id: int):

    user = get_user_by_id(db, user_id)

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
    