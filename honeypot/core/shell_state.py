"""Per-session shell state for the SSH emulator.

Every emulated command was previously answered from a dictionary rebuilt on
each call, so the shell had no memory: ``cd /tmp`` printed nothing and changed
nothing, and a file an attacker downloaded did not exist a command later. An
attacker who checks — and a dropper script that checks by running the thing it
just fetched — sees the emulation immediately.

This holds the small amount of state that makes a session self-consistent: the
working directory, and the files the attacker believes they created. Nothing
here touches the real filesystem; the "files" are names and sizes.
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field

#: Sessions tracked at once. A honeypot under a mass scan opens and abandons
#: connections continuously, so this is bounded and evicted oldest-first.
MAX_TRACKED_SESSIONS = 2048

#: Files remembered per session. A dropper writes a handful; anything writing
#: thousands is trying to exhaust memory rather than attack the host.
MAX_FILES_PER_SESSION = 64


@dataclass
class DroppedFile:
    """A file the attacker believes they put on the box."""

    name: str
    size: int
    executable: bool = False
    source_url: str | None = None
    created_at: float = field(default_factory=time.time)


@dataclass
class ShellState:
    """What one SSH session thinks the machine looks like."""

    cwd: str = "/home/user"
    files: dict[str, DroppedFile] = field(default_factory=dict)
    last_used: float = field(default_factory=time.time)

    def add_file(self, path: str, file: DroppedFile) -> None:
        if len(self.files) >= MAX_FILES_PER_SESSION:
            return
        self.files[path] = file

    def display_cwd(self, home: str = "/home/user") -> str:
        """The prompt form: ``~`` for home, ``~/x`` beneath it."""
        if self.cwd == home:
            return "~"
        if self.cwd.startswith(home + "/"):
            return "~/" + self.cwd[len(home) + 1:]
        return self.cwd


def resolve_path(cwd: str, arg: str, home: str = "/home/user") -> str:
    """Resolve a shell path argument the way a shell would.

    Handles ``~``, relative segments and ``..``. ``posixpath.normpath``
    collapses ``..`` textually, which is what a shell does for a path that has
    no symlinks in it — and this filesystem has none.
    """
    arg = (arg or "").strip().strip("'\"")
    if not arg or arg == "~":
        return home
    if arg.startswith("~/"):
        arg = posixpath.join(home, arg[2:])
    if not arg.startswith("/"):
        arg = posixpath.join(cwd, arg)
    resolved = posixpath.normpath(arg)
    return resolved if resolved.startswith("/") else "/"


class ShellStateStore:
    """Session id -> ShellState, bounded."""

    def __init__(self) -> None:
        self._states: dict[str, ShellState] = {}

    def get(self, session_id: str) -> ShellState:
        state = self._states.get(session_id)
        if state is None:
            self._evict()
            state = ShellState()
            self._states[session_id] = state
        state.last_used = time.time()
        return state

    def drop(self, session_id: str) -> None:
        self._states.pop(session_id, None)

    def _evict(self) -> None:
        if len(self._states) < MAX_TRACKED_SESSIONS:
            return
        stale = sorted(self._states.items(), key=lambda kv: kv[1].last_used)
        for session_id, _ in stale[: len(self._states) - MAX_TRACKED_SESSIONS + 1]:
            self._states.pop(session_id, None)


shell_states = ShellStateStore()
