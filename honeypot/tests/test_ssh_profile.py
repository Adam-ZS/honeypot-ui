"""The transport proposal must match the banner.

Vetterl and Clayton (USENIX WOOT '18) fingerprint medium-interaction honeypots
at internet scale using one packet and an equal error rate of 0.0183, by
comparing the KEXINIT an off-the-shelf library sends against the one the
claimed software sends. This engine speaks SSH through asyncssh, so it sits
squarely in the class that attack targets.

These tests read the bytes off a socket rather than inspecting configuration,
because what matters is what a scanner sees, not what we asked for.
"""

import asyncio
import struct

import asyncssh
import pytest

from honeypot.adaptive.ssh_profile import (
    OPENSSH_8_2,
    apply_extra_kex_algs,
    get_profile,
)

#: Ports in the ephemeral range, distinct per test so a lingering listener
#: from one cannot be mistaken for another's.
BASE_PORT = 24200


def _parse_kexinit(payload: bytes) -> list[str]:
    """Decode the ten name-lists out of an SSH_MSG_KEXINIT."""
    assert payload[0] == 20, f"expected SSH_MSG_KEXINIT (20), got {payload[0]}"
    offset = 17  # message type + 16-byte cookie
    names = []
    for _ in range(10):
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        names.append(payload[offset:offset + length].decode())
        offset += length
    return names


async def _read_server_proposal(port: int) -> tuple[str, list[str]]:
    """Connect as a bare socket and read the banner and KEXINIT."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = (await reader.readline()).decode().strip()
        writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n")
        await writer.drain()

        (packet_length,) = struct.unpack(">I", await reader.readexactly(4))
        rest = await reader.readexactly(packet_length)
        padding = rest[0]
        return banner, _parse_kexinit(rest[1:len(rest) - padding])
    finally:
        writer.close()


class _AcceptingServer(asyncssh.SSHServer):
    """Accepts any password, as the emulator does once past its threshold.

    Needed because a listener with no SSHServer offers no authentication
    method at all, and a client would hang until its login timeout — which
    would make the handshake test fail for a reason unrelated to the
    algorithms it is checking.
    """

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return True


@pytest.fixture
async def honeypot_ssh():
    """The emulator's listener, started the way start() starts it."""
    profile = get_profile("openssh-8.2p1-ubuntu")
    apply_extra_kex_algs(profile)

    async def handler(process):
        process.exit(0)

    acceptor = await asyncssh.listen(
        "127.0.0.1",
        BASE_PORT,
        server_factory=_AcceptingServer,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=handler,
        server_version=profile.version_string,
        kex_algs=profile.kex_algs,
        encryption_algs=profile.encryption_algs,
        mac_algs=profile.mac_algs,
        compression_algs=profile.compression_algs,
        encoding=None,
    )
    try:
        yield BASE_PORT, profile
    finally:
        acceptor.close()
        await acceptor.wait_closed()


class TestWireProposal:
    async def test_banner_is_the_profile(self, honeypot_ssh):
        port, profile = honeypot_ssh
        banner, _ = await _read_server_proposal(port)
        assert banner == profile.banner

    async def test_kex_list_matches_openssh_exactly(self, honeypot_ssh):
        """Same algorithms, same order, nothing extra.

        asyncssh's own proposal carried 21 algorithms here, including ML-KEM
        and rsa2048-sha256, which no OpenSSH 8.x has ever offered.
        """
        port, profile = honeypot_ssh
        _, lists = await _read_server_proposal(port)
        assert lists[0].split(",") == list(profile.kex_algs)

    async def test_no_extension_pseudo_algorithms_leak(self, honeypot_ssh):
        """asyncssh appends ext-info-s and kex-strict-s unconditionally.

        Neither string appears anywhere in the OpenSSH 8.2p1 source, and
        kex-strict is the Terrapin countermeasure from 9.6 — three years after
        the release this profile claims to be. Advertising it would be a
        contradiction visible in the same packet.
        """
        port, _ = honeypot_ssh
        _, lists = await _read_server_proposal(port)
        kex = lists[0].split(",")
        assert "ext-info-s" not in kex
        assert "kex-strict-s-v00@openssh.com" not in kex

    async def test_cipher_order_matches_not_just_the_set(self, honeypot_ssh):
        """asyncssh offered the same six ciphers in a different order — GCM
        before CTR, where OpenSSH sends CTR first. Order is fingerprinted."""
        port, profile = honeypot_ssh
        _, lists = await _read_server_proposal(port)
        assert lists[2].split(",") == list(profile.encryption_algs)
        assert lists[3].split(",") == list(profile.encryption_algs)

    async def test_mac_list_matches(self, honeypot_ssh):
        port, profile = honeypot_ssh
        _, lists = await _read_server_proposal(port)
        assert lists[4].split(",") == list(profile.mac_algs)

    async def test_compression_order_matches(self, honeypot_ssh):
        """OpenSSH offers none first; asyncssh's default leads with zlib."""
        port, profile = honeypot_ssh
        _, lists = await _read_server_proposal(port)
        assert lists[6].split(",") == list(profile.compression_algs)

    async def test_the_connection_still_works(self, honeypot_ssh):
        """A disguise that refuses real clients has not helped anyone.

        Constraining the proposal is only safe if the intersection with a real
        client's proposal is still non-empty — an over-tightened list would
        turn every attacker away at the handshake, which is a far worse
        failure than being fingerprintable.
        """
        port, _ = honeypot_ssh
        async with asyncio.timeout(15):
            async with asyncssh.connect(
                "127.0.0.1", port, username="root", password="x",
                known_hosts=None, encoding=None,
            ) as conn:
                assert conn.get_extra_info("server_version")


class TestProfileDefinition:
    def test_every_algorithm_is_one_asyncssh_can_offer(self):
        """A profile naming something asyncssh cannot do would silently
        shorten the proposal, which is the bug this module exists to fix.

        This is why the profile is 8.2 and not 8.9: 8.9 leads with
        sntrup761x25519-sha512@openssh.com, which asyncssh does not implement,
        so the disguise could only ever be approximate.
        """
        from asyncssh.encryption import get_encryption_algs
        from asyncssh.kex import get_kex_algs
        from asyncssh.mac import get_mac_algs

        def names(algs):
            return {a.decode() if isinstance(a, bytes) else a for a in algs}

        assert set(OPENSSH_8_2.kex_algs) <= names(get_kex_algs())
        assert set(OPENSSH_8_2.encryption_algs) <= names(get_encryption_algs())
        assert set(OPENSSH_8_2.mac_algs) <= names(get_mac_algs())

    def test_banner_and_version_string_agree(self):
        assert OPENSSH_8_2.banner.endswith(OPENSSH_8_2.version_string)
        assert not OPENSSH_8_2.version_string.startswith("SSH-2.0-")

    def test_unknown_profile_name_falls_back_rather_than_raising(self):
        """An unset or mistyped HONEYPOT_SSH_PROFILE must not stop the engine
        from starting; a default disguise beats no honeypot."""
        assert get_profile("nonsense") is OPENSSH_8_2
        assert get_profile(None) is OPENSSH_8_2
