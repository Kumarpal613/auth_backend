from asyncio.windows_events import NULL
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

@router.post("/password-recovery/request")
def request_password_recovery(request: auth.ForgotPasswordReq, db: db_dep):
    user = user_repo.get_user_by_email(db, request.email)

    if not user:
        # Always return the same response to prevent email enumeration attacks
        return {"message": "If an account with that email exists, a password recovery email has been sent."}

    # Only send email if user actually exists
    response_data = otp_service.send_recovery_otp(db, user)
    db.commit()
    return {"message": "If an account with that email exists, a password recovery email has been sent.", "recovery_token": response_data["recovery_token"]}

@router.post("/password-recovery/verify")
def verify_recovery_otp(data: auth.VerifyOTPRequest, db: db_dep, auth: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = auth.credentials
    email, reset_token = otp_service.verify_recovery_otp(db, token, data.otp)
    
    db.commit()
    return {
        "status": "success",
        "message": "OTP verified successfully. Please use the reset_token to establish a new password.",
        "reset_token": reset_token
    }

@router.post("/password-recovery/resend")
def resend_recovery_otp(db: db_dep, auth: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = auth.credentials
    response_data = otp_service.resend_recovery_otp(db, token)
    db.commit()
    return {"message": "A new OTP has been sent to your email.", "recovery_token": response_data["recovery_token"]}

@router.post("/password-recovery/reset")
def reset_password(request: auth.ResetPasswordReq, db: db_dep):
    # Verify the reset_session token using the token provided in the request body
    token = request.token
    payload = security.verify_jwt_token(token)
    
    if not payload or payload.get("type") != "reset_session":
        raise HTTPException(status_code=403, detail="Invalid token type or expired")
    
    user_email = payload.get("email")
    if not user_email:
        raise HTTPException(status_code=403,detail="Invalid token ")
    
    user = user_repo.get_user_by_email(db, user_email)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.password = security.hash_password(request.new_password)
    
    # We should delete the OTP tracker so this session cannot be reused.
    tracker_uuid = payload.get("sub")
    tracker = otp_repo.get_tracker_by_uuid(db, uuid=tracker_uuid)
    if tracker:
        otp_repo.delete_otp_tracker_by_tracker_id(db, tracker.id)
        
    db.commit()
    return {"message": "Password has been successfully updated."}

