"""One-time passcode issuance and verification."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import OTPVerification, User
from app.services.email import email_service

logger = logging.getLogger(__name__)

OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_LENGTH = 6


def _hash_code(code: str) -> str:
    """Hash an OTP for storage.

    Codes were previously stored in plaintext, so anyone with read access to
    the database (a backup, a SQL injection, a shared dev dump) could complete
    another user's verification or password reset.
    """
    settings = get_settings()
    return hmac.new(
        settings.SECRET_KEY.encode(), code.encode(), hashlib.sha256
    ).hexdigest()


class OTPService:
    async def generate_and_send(
        self,
        db: AsyncSession,
        user: User,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> bool:
        await self._invalidate_existing(db, user.id, purpose)

        otp_code = self._generate_code()
        otp_record = OTPVerification(
            user_id=user.id,
            email=user.email,
            otp_code=_hash_code(otp_code),
            purpose=purpose,
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=OTP_EXPIRY_MINUTES),
            ip_address=ip_address,
        )
        db.add(otp_record)
        await db.commit()

        # smtplib and urllib block; running them inline stalled the whole
        # event loop for the duration of the send.
        if purpose == "password_reset":
            sent = await asyncio.to_thread(
                email_service.send_password_reset_email,
                user.email,
                otp_code,
                user.name or "",
            )
        else:
            sent = await asyncio.to_thread(
                email_service.send_otp_email,
                user.email,
                otp_code,
                user.name or "",
            )

        if not sent:
            # Never log the code itself: application logs are routinely shipped
            # to third parties and would hand over every account.
            logger.error(
                "Failed to deliver %s OTP for user id %s", purpose, user.id
            )

        return sent

    async def verify(
        self,
        db: AsyncSession,
        user_id: int,
        otp_code: str,
        purpose: str = "email_verification",
    ) -> dict:
        result = await db.execute(
            select(OTPVerification)
            .where(
                OTPVerification.user_id == user_id,
                OTPVerification.purpose == purpose,
                OTPVerification.is_used.is_(False),
                OTPVerification.expires_at > datetime.now(timezone.utc),
            )
            .order_by(OTPVerification.created_at.desc())
            .limit(1)  # more than one live row raised MultipleResultsFound
        )
        otp_record = result.scalar_one_or_none()

        if not otp_record:
            return {
                "valid": False,
                "reason": "No active code found. Please request a new one.",
            }

        if otp_record.attempts >= OTP_MAX_ATTEMPTS:
            otp_record.is_used = True
            await db.commit()
            return {
                "valid": False,
                "reason": "Too many incorrect attempts. Please request a new code.",
            }

        # Constant-time comparison; a plain != leaks the code byte by byte.
        if not hmac.compare_digest(otp_record.otp_code, _hash_code(otp_code)):
            otp_record.attempts += 1
            remaining = OTP_MAX_ATTEMPTS - otp_record.attempts
            await db.commit()
            return {
                "valid": False,
                "reason": (
                    f"Invalid verification code. {remaining} attempt(s) remaining."
                    if remaining > 0
                    else "Too many incorrect attempts. Please request a new code."
                ),
            }

        otp_record.is_used = True
        otp_record.used_at = datetime.now(timezone.utc)
        await db.commit()

        return {"valid": True, "email": otp_record.email}

    async def resend(
        self,
        db: AsyncSession,
        user_id: int,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> bool:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            return False
        return await self.generate_and_send(db, user, purpose, ip_address)

    async def cleanup_expired(self, db: AsyncSession):
        await db.execute(
            delete(OTPVerification).where(
                OTPVerification.expires_at < datetime.now(timezone.utc)
            )
        )
        await db.commit()

    async def _invalidate_existing(
        self, db: AsyncSession, user_id: int, purpose: str
    ):
        result = await db.execute(
            select(OTPVerification).where(
                OTPVerification.user_id == user_id,
                OTPVerification.purpose == purpose,
                OTPVerification.is_used.is_(False),
            )
        )
        for record in result.scalars().all():
            record.is_used = True

    @staticmethod
    def _generate_code() -> str:
        # random.randint is a Mersenne Twister: observing a handful of codes
        # lets an attacker predict the rest. secrets uses the OS CSPRNG.
        return f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


otp_service = OTPService()
