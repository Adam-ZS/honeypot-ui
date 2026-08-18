"""Rate limiting is enforced and shares one limiter across all routers."""

import pytest


@pytest.fixture(autouse=True)
def enable_rate_limiting():
    """Re-enable the limiter that conftest disables for other tests."""
    from app.core.rate_limit import limiter

    limiter.enabled = True
    limiter.reset()
    yield
    limiter.reset()
    limiter.enabled = False


class TestRateLimiting:
    async def test_login_is_throttled(self, client):
        """The auth router used to build its own Limiter instance, so its
        limits were tracked in a store nothing else consulted."""
        payload = {"email": "nobody@example.com", "password": "whatever-long"}

        statuses = [
            (await client.post("/api/v1/auth/login", json=payload)).status_code
            for _ in range(14)
        ]
        assert 429 in statuses

    async def test_throttled_response_is_json(self, client):
        payload = {"email": "nobody@example.com", "password": "whatever-long"}
        last = None
        for _ in range(14):
            last = await client.post("/api/v1/auth/login", json=payload)
        assert last.status_code == 429
        assert "Rate limit exceeded" in last.json()["detail"]
