"""Fixtures for the engine tests.

The engine had no tests. Its emulation is the part of the system an attacker
actually touches, and the part where a wrong answer costs intelligence rather
than raising an exception — a shell that replies "command not found" to wget
does not fail, it just quietly stops learning anything.
"""

import os
import sys

import pytest_asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from honeypot.core.session import session_manager  # noqa: E402
from honeypot.core.shell_state import shell_states  # noqa: E402


@pytest_asyncio.fixture
async def session():
    """A live session id, with its shell state torn down afterwards."""
    session_id = await session_manager.create_session("ssh", "203.0.113.77", 44321)
    yield session_id
    shell_states.drop(session_id)
