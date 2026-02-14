from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Boolean, DateTime, ForeignKey, String
from datetime import datetime, timezone
from app.db.base import Base

class Otps(Base):
    __tablename__ = "otps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id : Mapped[int] = mapped_column(ForeignKey("users.id"))
    otp: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)

class PasswordRecovery(Base):

    __tablename__ = "password_recoveries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id : Mapped[int] = mapped_column(ForeignKey("users.id"))
    resend_count: Mapped[int] = mapped_column(default=0)
    count_try: Mapped[int] = mapped_column(default=0)
    created_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc),onupdate=lambda: datetime.now(timezone.utc))