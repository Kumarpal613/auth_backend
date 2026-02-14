from datetime import datetime
from ssl import create_default_context
from pydantic import BaseModel, ConfigDict, EmailStr
from uvicorn import Config


class UserProfileRes(BaseModel):
    email: EmailStr
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)