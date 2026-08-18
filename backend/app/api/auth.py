"""Authentication, email verification and password reset."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.rate_limit import limiter
from app.core.security import (
    REFRESH_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_password_hash,
    needs_rehash,
    require_role,
    verify_password,
)
from app.models import AuditLog, User, UserRole
from app.schemas import (
    AdminUserCreate,
    OTPResendRequest,
    OTPVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterResponse,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
    UserRoleUpdate,
)
from app.services.otp import otp_service

logger = logging.getLogger(__name__)
router = APIRouter()

#: Returned for every reset/resend request so the endpoint cannot be used to
#: discover which addresses have accounts.
_GENERIC_OTP_RESPONSE = {
    "message": "If an account exists for that address, a code has been sent."
}

#: Hashing a throwaway password keeps the failed-login path as slow as the
#: successful one, so response timing does not reveal whether a user exists.
_TIMING_DECOY = get_password_hash("timing-equalisation-decoy")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _token_pair(user: User) -> dict:
    claims = {"sub": str(user.id), "email": user.email, "role": user.role.value}
    return {
        "access_token": create_access_token(claims),
        "refresh_token": create_refresh_token(claims),
        "token_type": "bearer",
    }


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """Self-service registration.

    New accounts are always created as viewers. The payload schema has no
    `role` field: it previously did, which let anyone register as an admin.
    """
    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if existing.scalar_one_or_none():
        # Do not confirm the address is taken; a duplicate registration gets
        # the same response as a fresh one.
        return RegisterResponse(
            message=(
                "Registration received. Check your email for a verification "
                "code."
            ),
            email=user_data.email,
            requires_verification=True,
        )

    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        name=user_data.name,
        role=UserRole.VIEWER,
        is_active=False,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    client_ip = _client_ip(request)
    db.add(
        AuditLog(
            user_id=user.id,
            action="user_registered",
            resource_type="user",
            resource_id=user.id,
            ip_address=client_ip,
            details={"requires_verification": True},
        )
    )
    await db.commit()

    await otp_service.generate_and_send(
        db, user, "email_verification", client_ip
    )

    return RegisterResponse(
        message=(
            "Registration received. Check your email for a verification code."
        ),
        email=user.email,
        requires_verification=True,
    )


@router.post("/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(
    request: Request,
    data: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # Same response shape whether or not the account exists.
    invalid = HTTPException(
        status_code=400, detail="Invalid or expired verification code."
    )
    if not user or user.is_verified:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "email_verification"
    )
    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

    user.is_verified = True
    user.is_active = True
    db.add(
        AuditLog(
            user_id=user.id,
            action="email_verified",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return {"message": "Email verified successfully. You can now log in."}


@router.post("/resend-otp")
@limiter.limit("3/minute")
async def resend_otp(
    request: Request,
    data: OTPResendRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and not user.is_verified:
        await otp_service.generate_and_send(
            db, user, "email_verification", _client_ip(request)
        )

    return _GENERIC_OTP_RESPONSE


@router.post("/request-password-reset")
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request,
    data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await otp_service.generate_and_send(
            db, user, "password_reset", _client_ip(request)
        )

    return _GENERIC_OTP_RESPONSE


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # A missing user previously returned 404 while a bad code returned 400,
    # which turned this endpoint into an account-existence oracle.
    invalid = HTTPException(
        status_code=400, detail="Invalid or expired reset code."
    )
    if not user:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "password_reset"
    )
    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

    user.hashed_password = get_password_hash(data.new_password)
    db.add(
        AuditLog(
            user_id=user.id,
            action="password_reset",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return {"message": "Password reset successfully. You can now log in."}


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login(
    request: Request,
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.email == credentials.email)
    )
    user = result.scalar_one_or_none()

    if user is None:
        verify_password(credentials.password, _TIMING_DECOY)
        raise HTTPException(
            status_code=401, detail="Invalid email or password"
        )

    if not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=401, detail="Invalid email or password"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please verify your email before logging in.",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Transparently upgrade hashes stored with weaker parameters.
    if needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(credentials.password)

    user.last_login = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            user_id=user.id,
            action="user_login",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return _token_pair(user)


@router.post("/refresh", response_model=Token)
@limiter.limit("20/minute")
async def refresh_token(
    request: Request,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new token pair.

    The body is a typed model rather than a bare dict, and the token must
    carry the refresh type claim — an access token used to work here, and a
    refresh token used to work as an API credential.
    """
    claims = decode_token(payload.refresh_token, REFRESH_TOKEN_TYPE)

    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(
            status_code=401, detail="User not found or disabled"
        )

    return _token_pair(user)


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.id == current_user["id"])
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(User).order_by(User.email))
    return result.scalars().all()


@router.post(
    "/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def create_user(
    request: Request,
    user_data: AdminUserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Admin-only account creation, including role assignment."""
    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        name=user_data.name,
        role=UserRole(user_data.role.value),
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="user_created",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"role": user.role.value},
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: int,
    request: Request,
    payload: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user["id"] and payload.role.value != "admin":
        # Prevent an admin locking every administrator out of the system.
        raise HTTPException(
            status_code=400, detail="Cannot remove your own admin role"
        )

    user.role = UserRole(payload.role.value)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="user_role_changed",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"role": user.role.value},
        )
    )
    await db.commit()
    await db.refresh(user)
    return user
