"""Recursive de-obfuscation of attacker commands.

Section V.B.2 records the expert interviews concluding that obfuscated
commands "must be recursively decoded before TTP mapping", and states the
findings were incorporated. They were not. ``base64`` appeared in the codebase
only as a regex to *match on* and a MITRE label to attach — the payload itself
was never decoded, so a dropper that fetched its second stage through
``echo <b64> | base64 -d | sh`` was recorded as one suspicious string and
analysed no further.

That matters because obfuscation is where the actual intent lives. The outer
command is deliberately boring; the inner one names the C2 host.

Everything here is layered decoding of attacker-controlled input, so every
loop is bounded: depth, total output size, and the number of candidates per
layer. A decoder that expands without limit is a denial-of-service surface on
the component whose whole job is to accept hostile input.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List

#: How many nested encodings to unwrap. Real droppers rarely exceed three;
#: past that the cost is not worth paying on hostile input.
MAX_DEPTH = 4

#: Ceiling on decoded output per session, across all layers.
MAX_TOTAL_CHARS = 200_000

#: Candidates considered per layer, longest first.
MAX_CANDIDATES_PER_LAYER = 12

#: Shorter than this and base64 detection is mostly false positives — ordinary
#: words like "passwd" are valid base64.
MIN_B64_LEN = 16

_B64_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64_LEN)
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_URL_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")

#: Text is only accepted as "decoded" if it looks like something a shell would
#: run. Random bytes that happen to be valid base64 decode to noise, and
#: feeding that to the analyser produces confident nonsense.
_PRINTABLE_RE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]*$")


@dataclass
class Layer:
    """One successful decode, kept so the chain can be shown to an analyst."""

    depth: int
    encoding: str
    source: str
    decoded: str

    def as_dict(self) -> dict:
        return {
            "depth": self.depth,
            "encoding": self.encoding,
            # Truncated: the record is evidence, not a payload store.
            "source": self.source[:200],
            "decoded": self.decoded[:2000],
        }


@dataclass
class Result:
    layers: List[Layer] = field(default_factory=list)
    #: Original text plus every decoded layer, for downstream tool/intent
    #: matching to run over.
    combined: str = ""

    @property
    def max_depth(self) -> int:
        return max((layer.depth for layer in self.layers), default=0)

    def as_dict(self) -> dict:
        return {
            "layers": [layer.as_dict() for layer in self.layers],
            "layer_count": len(self.layers),
            "max_depth": self.max_depth,
            "encodings": sorted({layer.encoding for layer in self.layers}),
        }


def _looks_like_text(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    if not _PRINTABLE_RE.match(value):
        return False
    # Decoded random bytes are printable surprisingly often; require some
    # structure a command would actually have.
    return bool(re.search(r"[ /\-.:=;|&$(){}\[\]]", value)) or value.isalnum()


def _try_base64(candidate: str) -> str | None:
    # Base64 needs a length that is a multiple of four; attackers strip
    # padding often enough that restoring it is worth the attempt.
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_hex(candidate: str) -> str | None:
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_hex_escape(candidate: str) -> str | None:
    try:
        return bytes(
            int(byte, 16) for byte in re.findall(r"\\x([0-9a-fA-F]{2})", candidate)
        ).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _try_url(candidate: str) -> str | None:
    decoded = urllib.parse.unquote(candidate)
    return decoded if decoded != candidate else None


_DECODERS = (
    ("base64", _B64_RE, _try_base64),
    ("hex", _HEX_RE, _try_hex),
    ("hex_escape", _HEX_ESCAPE_RE, _try_hex_escape),
    ("url", _URL_RE, _try_url),
)


def deobfuscate(text: str) -> Result:
    """Unwrap nested encodings, returning each layer and the combined text."""
    result = Result(combined=text)
    if not text:
        return result

    budget = MAX_TOTAL_CHARS
    frontier = [text]
    seen: set[str] = {text}

    for depth in range(1, MAX_DEPTH + 1):
        next_frontier: List[str] = []

        for chunk in frontier:
            for encoding, pattern, decoder in _DECODERS:
                candidates = sorted(
                    set(pattern.findall(chunk)), key=len, reverse=True
                )[:MAX_CANDIDATES_PER_LAYER]

                for candidate in candidates:
                    decoded = decoder(candidate)
                    if not decoded or not _looks_like_text(decoded):
                        continue
                    if decoded in seen or decoded == candidate:
                        continue

                    budget -= len(decoded)
                    if budget <= 0:
                        return _finalise(result)

                    seen.add(decoded)
                    result.layers.append(
                        Layer(depth=depth, encoding=encoding,
                              source=candidate, decoded=decoded)
                    )
                    next_frontier.append(decoded)

        if not next_frontier:
            break
        frontier = next_frontier

    return _finalise(result)


def _finalise(result: Result) -> Result:
    if result.layers:
        result.combined = result.combined + "\n" + "\n".join(
            layer.decoded for layer in result.layers
        )
    return result


def deobfuscate_commands(commands: List[str]) -> Result:
    """Run the whole command list as one document.

    Attackers split an encoded blob across several lines (``echo A >> f``,
    ``echo B >> f``, ``base64 -d f | sh``), so decoding each command in
    isolation misses the payload that only exists once they are joined.
    """
    return deobfuscate("\n".join(commands))
