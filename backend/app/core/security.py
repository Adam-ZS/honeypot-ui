"""Password hashing, JWT issuance and role enforcement."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import Settings, get_settings

security = HTTPBearer()

#: OWASP's 2023 floor for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000

#: Distinguishes an access token from a refresh token. Without it a refresh
#: token was accepted as an API credential and vice versa.
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired token",
    headers={"WWW-Authenticate": "Bearer"},
)


def _derive(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), iterations
    ).hex()


def get_password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = _derive(password, salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(plain_password: str, stored: str) -> bool:
    """Verify a password against a stored hash.

    Accepts both the current ``algo$iterations$salt$hash`` format and the
    legacy ``salt:hash`` format so existing accounts keep working. A malformed
    value returns False instead of raising, which previously turned a corrupt
    row into a 500 on the login endpoint.
    """
    if not stored:
        return False

    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt, digest = stored.split("$", 3)
            candidate = _derive(plain_password, salt, int(iterations))
        elif ":" in stored:
            salt, digest = stored.split(":", 1)
            candidate = _derive(plain_password, salt, 100_000)
        else:
            return False
    except (ValueError, TypeError):
        return False

    return secrets.compare_digest(candidate, digest)


def needs_rehash(stored: str) -> bool:
    """True when a stored hash uses weaker parameters than we now issue."""
    return not stored.startswith(f"pbkdf2_sha256${PBKDF2_ITERATIONS}$")


def _create_token(
    data: dict,
    token_type: str,
    expires_delta: timedelta,
    settings: Optional[Settings] = None,
) -> str:
    settings = settings or get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "typ": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    settings = settings or get_settings()
    return _create_token(
        data,
        ACCESS_TOKEN_TYPE,
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        settings,
    )


def create_refresh_token(
    data: dict, settings: Optional[Settings] = None
) -> str:
    settings = settings or get_settings()
    return _create_token(
        data,
        REFRESH_TOKEN_TYPE,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        settings,
    )


def decode_token(
    token: str,
    expected_type: str = ACCESS_TOKEN_TYPE,
    settings: Optional[Settings] = None,
) -> dict:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except JWTError:
        raise _CREDENTIALS_ERROR

    if payload.get("typ") != expected_type:
        raise _CREDENTIALS_ERROR
    return payload


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    payload = decode_token(credentials.credentials, ACCESS_TOKEN_TYPE)

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise _CREDENTIALS_ERROR

    role = payload.get("role", "viewer")
    if role not in ROLE_HIERARCHY:
        raise _CREDENTIALS_ERROR

    return {"id": user_id, "email": payload.get("email"), "role": role}


async def verify_honeypot_token(request: Request) -> bool:
    """Authenticate the honeypot engine on service-to-service routes.

    Uses a constant-time comparison: a plain `!=` on a shared secret leaks it
    through response timing one byte at a time.
    """
    settings = get_settings()
    supplied = request.headers.get("X-Honeypot-Token", "")
    if not secrets.compare_digest(supplied, settings.HONEYPOT_INGEST_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid honeypot token",
        )
    return True


def require_role(required_role: str):
    """Dependency enforcing a minimum role."""
    required_rank = ROLE_HIERARCHY[required_role]

    async def role_checker(current_user: dict = Depends(get_current_user)):
        if ROLE_HIERARCHY.get(current_user["role"], 0) < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker
