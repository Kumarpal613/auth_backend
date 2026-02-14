from mailbox import Message
import stat
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordRequestForm

from app.db.session import get_db
from app.models.user import User
from app.models.tokens import RefreshToken
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
)
from app.core.config import settings
from app.repositories.refresh_repo import create_refresh_record, query_refresh_token
from app.schemas import auth
from app.services.auth_service import create_refresh_and_access_tokens, deliver_otp_to_user, handle_password_recovery, refresh_token_service
from app.repositories.user_repo import create_user, get_user_by_email, get_user_by_id

router = APIRouter(prefix="/auth", tags=["Auth"])

db_dep = Annotated[Session,Depends(get_db)]
form_dep = Annotated[OAuth2PasswordRequestForm,Depends()]

@router.post("/login")
def login( response: Response, db: db_dep , form_data:form_dep ):

    user = get_user_by_email(db, form_data.username)

    auth_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user or not verify_password(form_data.password, user.password_hash):
        raise auth_exception

    access_token, refresh_token = create_refresh_and_access_tokens(db, user.id)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS*24*60*60
    )

    return {"access_token": access_token}

@router.post("/signup")
def signup(response: Response, db: db_dep, user_data: auth.SignupReq ):

    existing_user = db.query(User).filter(User.email == user_data.email).first()
    
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail= "Email already registered")

    create_user(db, user_data)

    return {"message":"User created Successfully"}

@router.get("/refresh")
def refresh(request: Request, response: Response, db:db_dep):

    old_refresh = request.cookies.get("refresh_token")

    if not old_refresh:
        raise HTTPException(401, "No refresh token provided")
    
    access_token, new_refresh = refresh_token_service(db, old_refresh)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS*24*60*60   
    )

    return {"access_token": access_token}

@router.post("/logout")
def logout(request: Request, response: Response, db: db_dep):

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)

        query_refresh_token(db, token_hash).update({"revoked": True})

        db.commit()
        
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )

    return {"message": "Successfully Logged out"}

@router.post("/logout_all")
def logout_all(request: Request, response: Response, db: db_dep):
    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        current_user = query_refresh_token(db, token_hash).first()
        if current_user :

            db.query(RefreshToken).filter(
                RefreshToken.user_id == current_user.user_id,
                RefreshToken.revoked == False
            ).update({"revoked": True})

            db.commit()

            user = get_user_by_id(db,current_user.user_id)
            if user:
                user.token_version += 1
                db.commit()

    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )

    return {"message": "Logged out from all devices"}



        

    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )

    return {"message": "Successfully Logged out"}

@router.post("/password-recovery/request")
def recover_password(email: str, db: db_dep):
    user = get_user_by_email(db, email)

    if not user:
        # Always return the same response to prevent email enumeration attacks
        raise HTTPException(status_code=status.HTTP_200_OK, detail="If an account with that email exists, a password recovery email has been sent.")

     # Only send email if user actually exists
    create_password_recovery = handle_password_recovery(db,user.id)
    deliver_otp_to_user(db,user.id,email=user.email)

@router.post("/password-recovery/verify")
def verify_recovery_token(token: str, db: db_dep):
    pass

@router.post("/auth/password-recovery/resend")
def resend_recovery_token(email: str, db: db_dep):
    pass

@router.post("/auth/password-recovery/reset")
def reset_password(request: auth.ResetPasswordReq, db: db_dep):
    # {
    # "reset_token": "jwt_or_random_token",
    # "new_password": "Strong@123"
    # }
    pass

