from pydantic import BaseModel
from datetime import datetime


class AccessTokenPayload(BaseModel):
    sub: int              # user_id
    tv: int               # token_version
    exp: datetime         # expiration time


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TempTokenResponse(BaseModel):
    temp_token: str
    token_type: str = "bearer"