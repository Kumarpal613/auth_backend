from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from datetime import datetime, timezone
from app.db.base import Base
import uuid
from sqlalchemy.dialects.postgresql import UUID

class Otps(Base):
    __tablename__ = "otps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tracker_id: Mapped[int] = mapped_column(
        ForeignKey("otp_tracker.id",ondelete="CASCADE"), nullable=False
    )
    otp: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)


class OtpTracker(Base):
    __tablename__ = "otp_tracker"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        default=uuid.uuid4, 
        unique=True, 
        index=True
    )

    user_id: Mapped[int] = mapped_column(Integer)
    is_temp: Mapped[bool] = mapped_column(Boolean, default=False)

    # State Flags (Indexed for high-speed lookups)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    blocked_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    attempts_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    ) 
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_edit_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (UniqueConstraint("user_id", "is_temp", name="uq_user_temp"),)
