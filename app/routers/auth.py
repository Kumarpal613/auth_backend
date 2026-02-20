from mailbox import Message
import stat
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials

from app.db.session import get_db
from app.core import security
from app.core.config import settings
from app.models.tokens import RefreshToken
from app.schemas import auth
from app.services import auth_service
from app.services import otp_service
from app.repositories import  refresh_repo, user_repo,otp_repo


router = APIRouter(prefix="/auth", tags=["Auth"])

db_dep = Annotated[Session,Depends(get_db)]
form_dep = Annotated[OAuth2PasswordRequestForm,Depends()]
security_scheme = HTTPBearer()

@router.post("/signup")
def signup(response: Response, db: db_dep, user_data: auth.SignupReq ):

    existing_user = user_repo.get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail= "Email already registered")
    
    temp_user = user_repo.get_temp_user_by_email(db, user_data.email)
    user_data.password = security.hash_password(user_data.password)
    if temp_user is None:
        temp_user = user_repo.create_temp_user(db, user_data)
    else:
        temp_user.password = user_data.password
        db.flush()
    
    jwt_token = otp_service.send_signup_otp(db, temp_user)["signup_token"]

    db.commit()
    return {"message": "An  Otp has been sent to your email. Please verify to complete registration.","signup_token": jwt_token}

@router.post("/signup/verify-otp")
def verify_signup_otp(request: Request, db: db_dep, data: auth.VerifyOTPRequest, auth: HTTPAuthorizationCredentials = Depends(security_scheme)):

    token = auth.credentials
    temp_user_email = otp_service.verify_signup_otp(db, token, data.otp)
    
    if temp_user_email:
        auth_service.register_permanent_user(db,temp_user_email)
        temp_user = user_repo.get_temp_user_by_email(db,temp_user_email)
        if temp_user:
            otp_repo.delete_otp_tracker_by_tracker_id(db,temp_user.id)

        db.delete(temp_user)
        
        db.commit()
        return {
            "status": "success",
            "message": "Account verified and created successfully!"
        }
    
    raise HTTPException(status_code=400, detail="Verification failed")

@router.post("/signup/resend-otp")
def resend_signup_otp(request: Request, db: db_dep,auth: HTTPAuthorizationCredentials = Depends(security_scheme)):

    token = auth.credentials
    jwt_token = otp_service.resend_signup_otp(db, token)["signup_token"]
    db.commit()
    return {"message": "An  Otp has been sent to your email. Please verify to complete registration.","signup_token": jwt_token}

@router.post("/login")
def login( response: Response, db: db_dep , form_data:form_dep ):

    user = user_repo.get_user_by_email(db, form_data.username)

    auth_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user or not security.verify_password(password=form_data.password,hashed= user.password):
        raise auth_exception

    access_token, refresh_token = auth_service.create_refresh_and_access_tokens(db, user.id)

    

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS*24*60*60
    )
    db.commit()
    return {"access_token": access_token}

@router.post("/refresh")
def refresh(request: Request, response: Response, db:db_dep):

    old_refresh = request.cookies.get("refresh_token")

    if not old_refresh:
        raise HTTPException(401, "No refresh token provided")
    
    user = auth_service.verify_refresh_token_and_revoke(db,old_refresh)
    if user is None :
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail={"message":"User  not found"})
    
    access_token, new_refresh = auth_service.create_refresh_and_access_tokens(db,user.id)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS*24*60*60   
    )
    db.commit()
    return {"access_token": access_token}

@router.post("/logout")
def logout(request: Request, response: Response, db: db_dep):

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        user = auth_service.verify_refresh_token_and_revoke(db,refresh_token)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail={"message":" Refresh Token Required"}) 
          
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )
    db.commit()
    return {"message": "Successfully Logged out"}

@router.post("/logout_all")
def logout_all(request: Request, response: Response, db: db_dep):

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        user = auth_service.verify_refresh_token_and_revoke(db,refresh_token)
        if user:
            user.token_version += 1
            db.flush()
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail={"message":" Refresh Token Required"}) 
    
    
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )
    db.commit()
    return {"message": "Logged out from all devices"}

# @router.post("/password-recovery/request")
# def recover_password(email: str, db: db_dep):
#     user = get_user_by_email(db, email)

#     if not user:
#         # Always return the same response to prevent email enumeration attacks
#         raise HTTPException(status_code=status.HTTP_200_OK, detail="If an account with that email exists, a password recovery email has been sent.")

#      # Only send email if user actually exists
#     create_password_recovery = handle_password_recovery(db,user.id)
#     deliver_otp_to_user(db,user.id,email=user.email)

# @router.post("/password-recovery/verify")
# def verify_recovery_token(token: str, db: db_dep):
#     pass

# @router.post("/auth/password-recovery/resend")
# def resend_recovery_token(email: str, db: db_dep):
#     pass

# @router.post("/auth/password-recovery/reset")
# def reset_password(request: auth.ResetPasswordReq, db: db_dep):
#     # {
#     # "reset_token": "jwt_or_random_token",
#     # "new_password": "Strong@123"
#     # }
#     pass

