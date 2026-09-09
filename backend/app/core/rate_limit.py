"""Shared rate limiter.

Each router previously constructed its own Limiter, so the limits registered
by the auth router were tracked in a different store from the one attached to
app.state. A single instance keeps counters consistent and lets the
RateLimitExceeded handler fire for every route.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings


def _client_key(request) -> str:
    """Identify the client, honouring a trusted proxy header when configured.

    Behind Render/Vercel the socket address is the proxy, so without this every
    request shares one bucket.
    """
    settings = get_settings()
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_client_key)
