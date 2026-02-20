from pydantic import EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Any
import os
from pathlib import Path

current_file_dir = Path(__file__).resolve().parent  # app/core
project_root = current_file_dir.parent.parent  # project_root
env_path = project_root / ".env"


class Settings(BaseSettings):
    DATABASE_URL: str

    JWT_SECRET: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 8
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SIGNUP_TOKEN_EXPIRE_MINUTES: int = 15
    COOKIE_SECURE: bool = True

    OTP_EXPIRE_MINUTES: int = 10
    MAX_OTP_ATTEMPTS: int = 2
    MAX_OTP_RESENDS: int = 4
    RESEND_COOLDOWN_SECONDS: int = 30

    APP_EMAIL: EmailStr
    EMAIL_PASSWORD: str

    TEMP_USER_EXPIRE_HOURS: int = 48
    OTP_TRACKER_EXPIRE_HOURS: int = 24
    MAX_UNBLOCK_REQUEST: int = 1
    OTP_TRACKER_LOCK_MINUTES: int = 30

    

    model_config = SettingsConfigDict(
        env_file=env_path, env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()  # pyright: ignore[reportCallIssue]
