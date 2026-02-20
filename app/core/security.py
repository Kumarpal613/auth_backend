from fastapi import HTTPException, status
import jwt
from datetime import datetime, timedelta, timezone
from typing import Annotated
from pwdlib import PasswordHash
from jwt.exceptions import InvalidTokenError
import hashlib
import secrets

from app.core.config import settings

password_hash = PasswordHash.recommended()

def hash_password(password: str)->str:

    return password_hash.hash(password)

def verify_password(password: str, hashed: str)->bool :
    return password_hash.verify(password, hashed)

def create_jwt_token(payload,jwt_secret=settings.JWT_SECRET,algorithm=settings.JWT_ALGORITHM):
    return jwt.encode(payload, jwt_secret, algorithm=algorithm)

def verify_jwt_token(token, jwt_secret=settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM):
    try :
        payload =jwt.decode(token,jwt_secret,algorithms=[algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={f"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_access_token(user_id: int, token_version: int, role: str = "User"):

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expires,
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token() -> str:
    return secrets.token_urlsafe(64)

def hash_refresh_token(token: str) -> str:

    return hashlib.sha256(token.encode()).hexdigest()

def decode_access_token(token: str):
    try :
        payload =jwt.decode(token,settings.JWT_SECRET,algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def genenate_temp_password_token():
    return secrets.token_urlsafe(32)

def hash_temp_password_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def verify_temp_password_token_hash(token: str, token_hash: str) -> bool:
    return hash_temp_password_token(token) == token_hash

def generate_otp() :
    return str(secrets.randbelow(1000000)).zfill(6)

def hash_otp(otp: str):
    return hashlib.sha256(otp.encode()).hexdigest()

def verify_otp(otp: str, otp_hash: str) -> bool:
    return hash_otp(otp) == otp_hash

