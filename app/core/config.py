
from pydantic import EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Any
import os
from pathlib import Path

current_file_dir = Path(__file__).resolve().parent # app/core
project_root = current_file_dir.parent.parent      # project_root
env_path = project_root / ".env"


class Settings(BaseSettings):
    DATABASE_URL : str 

    JWT_SECRET : str 
    JWT_ALGORITHM : str 
    ACCESS_TOKEN_EXPIRE_MINUTES : int = 8
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    COOKIE_SECURE: bool = True

    otp_expire_minutes: int = 10
    password_recovery_max_try: int = 10
    resend_opt_max_try: int = 5
    password_recovery_cooldown_minutes: int = 30

    APP_EMAIL: EmailStr
    EMAIL_PASSWORD: str

    model_config = SettingsConfigDict(
        env_file = env_path,
        env_file_encoding="utf-8",
        extra="ignore"
    )



settings = Settings()  # pyright: ignore[reportCallIssue]


