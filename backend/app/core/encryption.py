"""Encryption at rest for captured attacker commands and payloads."""

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    """Derive a Fernet key from the configured secret.

    The previous implementation space-padded the raw setting to 32 bytes and
    base64'd it, so a short key produced a mostly-constant key and the padding
    contributed no entropy. Hashing gives a full-width key from any input.
    """
    settings = get_settings()
    digest = hashlib.sha256(settings.ENCRYPTION_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_data(data: str) -> str:
    return _get_fernet().encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt a stored blob.

    Raises ValueError rather than the library's InvalidToken so callers do not
    have to import cryptography to handle a rotated key.
    """
    try:
        return _get_fernet().decrypt(encrypted_data.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Could not decrypt stored data; ENCRYPTION_KEY may have changed"
        ) from exc
