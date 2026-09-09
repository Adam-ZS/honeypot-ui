"""SSH transport profiles that match the banner they claim.

Vetterl and Clayton, "Bitter Harvest: Systematically Fingerprinting Low- and
Medium-interaction Honeypots at Internet Scale" (USENIX WOOT '18), fingerprint
Kippo and Cowrie with a single packet at an equal error rate of 0.0183. The
attack does not look at the shell at all. It looks at the SSH transport:

    low- and medium-interaction honeypots use off-the-shelf libraries for the
    transport layer, and those libraries implement the protocol subtly
    differently from the system being impersonated.

That is exactly this engine's position. The banner said
``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` and then asyncssh sent its own
default KEXINIT. Read off the wire, that proposal carried 21 key exchange
algorithms where OpenSSH 8.9 offers 10, among them ``mlkem768x25519-sha256``,
``mlkem768nistp256-sha256``, ``mlkem1024nistp384-sha384`` and
``rsa2048-sha256`` — post-quantum and RSA key exchange that no OpenSSH 8.9
has ever offered — and 15 MACs where OpenSSH offers 10. The cipher *set*
happened to match, but the order did not: asyncssh sent the GCM modes before
the CTR modes, and OpenSSH sends CTR first. Ordering is part of what the
paper fingerprints, so matching the set is not enough.

All of it arrives in the second packet of the connection, before
authentication, to anyone who looks.

So the proposal is pinned to a real OpenSSH release's documented defaults, in
that release's exact order, and the banner is chosen from the same profile
rather than independently. The two can no longer contradict each other.

Which release: 8.2p1, not the 8.9p1 the banner rotation preferred. 8.9 offers
``sntrup761x25519-sha512@openssh.com`` first, and asyncssh cannot implement it,
so claiming 8.9 would leave a missing algorithm at the head of the list — a
smaller tell than the current one but still a tell. 8.2's default proposal is
entirely within what asyncssh can offer, so the match is exact rather than
approximate. Choosing the version we can imitate perfectly over the version we
would prefer to be is the whole trade.

Lists are transcribed from sshd_config(5) as shipped in OpenBSD 6.7 (the
OpenSSH 8.2/8.3 era) and cross-checked against ssh -G on a running system.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SSHProfile:
    """One OpenSSH release, banner and transport proposal together."""

    name: str
    banner: str
    kex_algs: tuple[str, ...]
    encryption_algs: tuple[str, ...]
    mac_algs: tuple[str, ...]
    compression_algs: tuple[str, ...]
    #: Pseudo-algorithms appended to the kex name-list. asyncssh always adds
    #: ``ext-info-s`` and ``kex-strict-s-v00@openssh.com``; whether the claimed
    #: release does depends entirely on its age, and getting this wrong is its
    #: own single-packet tell. Measured, not assumed: a real OpenSSH 10.5
    #: server sends both, and neither string appears anywhere in the OpenSSH
    #: 8.2p1 source, so an 8.2 server sends neither.
    extra_kex_algs: tuple[str, ...] = ()

    #: Host key types a stock install of this release actually has. Ubuntu and
    #: Debian generate all three at package install, so a server offering only
    #: ed25519 is already unusual.
    host_key_algs: tuple[str, ...] = field(
        default=("ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256")
    )

    @property
    def version_string(self) -> str:
        """The part after ``SSH-2.0-``, which is what asyncssh wants."""
        return self.banner.split("SSH-2.0-", 1)[-1]


#: OpenSSH 8.2p1 as shipped in Ubuntu 20.04 LTS. Still the most common single
#: SSH version on the internet at the time of writing, which also makes it the
#: least remarkable thing to be.
OPENSSH_8_2 = SSHProfile(
    name="openssh-8.2p1-ubuntu",
    banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9",
    kex_algs=(
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ),
    encryption_algs=(
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    ),
    mac_algs=(
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    ),
    # OpenSSH offers no compression until after authentication, and advertises
    # it in this order.
    compression_algs=("none", "zlib@openssh.com"),
    # 8.2 advertises neither. kex-strict is the Terrapin countermeasure and
    # arrived in 9.6, three years later; an 8.2 server offering it is a
    # contradiction. ext-info-s is absent from the 8.2 source too — in RFC 8308
    # it is the client that sends ext-info-c, which 8.2's kex_choose_conf
    # matches against, without the server advertising its own half.
    extra_kex_algs=(),
)

#: Debian 11. Same proposal as 8.2 — nothing in the default lists changed
#: between them — so the banner can differ while the transport stays exact.
OPENSSH_8_4_DEBIAN = SSHProfile(
    name="openssh-8.4p1-debian",
    banner="SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
    kex_algs=OPENSSH_8_2.kex_algs,
    encryption_algs=OPENSSH_8_2.encryption_algs,
    mac_algs=OPENSSH_8_2.mac_algs,
    compression_algs=OPENSSH_8_2.compression_algs,
    extra_kex_algs=(),
)

PROFILES = {p.name: p for p in (OPENSSH_8_2, OPENSSH_8_4_DEBIAN)}

DEFAULT_PROFILE = OPENSSH_8_2


def get_profile(name: str | None = None) -> SSHProfile:
    return PROFILES.get(name or "", DEFAULT_PROFILE)


def apply_extra_kex_algs(profile: SSHProfile) -> bool:
    """Make asyncssh advertise the profile's extension names, not its own.

    asyncssh appends ``ext-info-s`` and ``kex-strict-s-v00@openssh.com`` to
    every server proposal. Both are correct for a current OpenSSH and wrong for
    the release this honeypot claims to be, and they sit in the same packet
    that Bitter Harvest reads. There is no public option for it, so the one
    private method that produces them is replaced.

    Suppressing the name is not sufficient on its own. asyncssh decides whether
    strict key exchange is in force from the *peer's* advertisement alone
    (connection.py, ``_process_kexinit``), on the assumption that it always
    advertises its own half. Drop our half and a client offering
    ``kex-strict-c-v00@openssh.com`` leaves the server enforcing strict-kex
    sequence rules while the client does not — the two desynchronise after
    NEWKEYS and the connection hangs until the client's login timeout. Measured:
    every connection failed with the name suppressed and the flag left alone.

    RFC-wise the server is in the wrong there; strict-kex is only in force when
    both ends offer it. So the flag is bound to what we actually advertised.

    Guarded rather than assumed: if a future asyncssh drops or renames either
    piece, the honeypot keeps working and says that this particular disguise
    slipped, instead of failing to start.

    Returns True when the patch was applied.
    """
    import logging

    from asyncssh.connection import SSHConnection

    logger = logging.getLogger(__name__)

    if not hasattr(SSHConnection, "_get_extra_kex_algs"):
        logger.warning(
            "asyncssh no longer defines _get_extra_kex_algs; the SSH kex "
            "proposal will carry its defaults and will not match the %s "
            "banner exactly",
            profile.name,
        )
        return False

    extra = [alg.encode() for alg in profile.extra_kex_algs]
    advertises_strict = b"kex-strict-s-v00@openssh.com" in extra
    client_extra = [b"ext-info-c", b"kex-strict-c-v00@openssh.com"]

    def _get_extra_kex_algs(self):
        # Only the server half is ours to shape. Anything asyncssh does as a
        # client is left alone, since the engine never dials out.
        return client_extra if self.is_client() else list(extra)

    SSHConnection._get_extra_kex_algs = _get_extra_kex_algs

    # Bind strict-kex to our own advertisement, not just the peer's.
    _STORE = "_honeypot_strict_kex"

    def _get_strict(self) -> bool:
        return getattr(self, _STORE, False)

    def _set_strict(self, value: bool) -> None:
        if value and self.is_server() and not advertises_strict:
            value = False
        setattr(self, _STORE, value)

    SSHConnection._strict_kex = property(_get_strict, _set_strict)
    return True
