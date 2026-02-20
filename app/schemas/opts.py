from enum import Enum
from typing import Optional

from pydantic import BaseModel

class TrackerState(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    RESEND_EXHAUSTED = "resend_exhausted"
    SIGNUP_BLOCKED = "signup_blocked"
