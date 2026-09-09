"""Telling research scanners apart from attackers.

A honeypot on a public address is scanned continuously by organisations that
are not attacking it: Censys, Shodan, Rapid7, Shadowserver, academic measurement
projects. GreyNoise's 2024 profiling of benign scanners puts this at the
majority of unsolicited traffic reaching an arbitrary address.

The pipeline classified all of it as ``reconnaissance``. That is not a bug in
the classifier — a Censys probe genuinely is reconnaissance — but it makes
every number the project reports meaningless. "Sessions observed", "attacks by
country", "reconnaissance is our largest category": all of them are dominated
by traffic that was never adversarial, and none of them can be compared against
anything.

So sessions are attributed rather than dropped. A scan from Censys is still
recorded in full — it is real data about what the internet does to an exposed
host — but it is labelled, and it can be excluded from the counts that are
supposed to describe attackers.

Dropping would be worse than useless: attackers do use scanner-adjacent
infrastructure, the lists go stale, and a honeypot that silently discards
traffic cannot be audited.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

#: Seed list of networks operated by organisations that publish their scanning
#: activity and offer opt-out. Each entry is documented by its operator; they
#: are listed here so the project has a working default with no network
#: dependency at ingest time.
#:
#: This is a seed, not a maintained feed, and it will go stale. Point
#: SCANNER_LIST_PATH at a MISP warninglist export (the ``*-scanning`` lists at
#: github.com/MISP/misp-warninglists) to override it with something current.
SEED_NETWORKS: dict[str, tuple[str, ...]] = {
    "censys": (
        "162.142.125.0/24",
        "167.94.138.0/24",
        "167.94.145.0/24",
        "167.94.146.0/24",
        "167.248.133.0/24",
        "199.45.154.0/24",
        "199.45.155.0/24",
    ),
    "shodan": (
        "198.20.69.0/24",
        "198.20.70.0/24",
        "198.20.99.0/24",
        "66.240.192.0/24",
        "66.240.219.0/24",
        "71.6.128.0/17",
        "80.82.77.0/24",
        "82.221.105.0/24",
    ),
    "rapid7": (
        "5.63.151.96/27",
        "71.6.216.0/24",
        "146.185.25.0/24",
    ),
    "shadowserver": (
        "184.105.139.0/24",
        "184.105.247.0/24",
        "216.218.206.0/24",
    ),
}


class ScannerRegistry:
    """Which known scanner, if any, an address belongs to."""

    def __init__(self) -> None:
        self._networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._loaded = False

    def _compile(self, source: dict[str, Iterable[str]]) -> None:
        compiled = []
        for operator, cidrs in source.items():
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    logger.warning("Skipping malformed scanner network %r", cidr)
                    continue
                # A /32 of 0.0.0.0 or an all-addresses net would match
                # everything; refuse rather than silently label the internet.
                if network.prefixlen == 0 or network.network_address.is_unspecified:
                    continue
                compiled.append((network, operator))
        # Longest prefix first, so a specific entry wins over a broad one.
        compiled.sort(key=lambda item: item[0].prefixlen, reverse=True)
        self._networks = compiled

    def load(self) -> None:
        """Load the override list if configured, else the seed."""
        if self._loaded:
            return
        self._loaded = True

        path = os.getenv("SCANNER_LIST_PATH")
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                # MISP warninglist shape: {"name": ..., "list": [...]}. A plain
                # {operator: [cidr, ...]} mapping is accepted too.
                if isinstance(data, dict) and isinstance(data.get("list"), list):
                    source = {str(data.get("name") or "scanner"): data["list"]}
                elif isinstance(data, dict):
                    source = {k: v for k, v in data.items() if isinstance(v, list)}
                else:
                    raise ValueError("unrecognised scanner list format")
                self._compile(source)
                logger.info(
                    "Loaded %d scanner networks from %s", len(self._networks), path
                )
                return
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Could not read scanner list at %s (%s); using the seed list",
                    path,
                    exc,
                )

        self._compile(SEED_NETWORKS)

    def identify(self, ip: str) -> Optional[str]:
        """The operator scanning from this address, or None."""
        self.load()
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, operator in self._networks:
            if address in network:
                return operator
        return None


scanner_registry = ScannerRegistry()
