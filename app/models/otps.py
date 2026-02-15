from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from datetime import datetime, timezone
from app.db.base import Base
from app.models import user

class Otps(Base):
    __tablename__ = "otps"

    tracker_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    otp: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)

class OtpTracker(Base):
    __tablename__ = "otp_tracker"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id : Mapped[int] = mapped_column(Integer)
    is_temp : Mapped[bool] = mapped_column(Boolean, default=False)

    resend_count: Mapped[int] = mapped_column(Integer, default=0)
    attempts_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] =mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc), onupdate= lambda:datetime.now(timezone.utc))

