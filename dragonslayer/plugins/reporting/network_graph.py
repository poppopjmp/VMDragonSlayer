"""
Network Graph Analyser
=======================

Ported from ``repos/stage6/working/network-graph/network_analyzer.py``.

Extracts hostnames/domains from binary strings (ASCII + UTF-16) and,
when analysing a directory of samples, builds an infrastructure-sharing
network graph.

No heavy dependencies — uses only the standard library.
"""

from __future__ import annotations

import logging
import re
import struct
import time
from typing import Any

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

VALID_SUFFIXES = {
    "com", "de", "org", "eu", "net", "co", "us", "uk", "ru", "cn", "jp",
    "br", "au", "in", "it", "fr", "ca", "es", "pl", "nl", "kr", "se",
    "ch", "be", "at", "cz", "gr", "no", "dk", "fi", "pt", "hu", "ro",
    "io", "dev", "app", "cloud", "info", "biz", "me", "tv", "cc", "xyz",
}

_HOSTNAME_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
)


def _detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if len(data) >= 4:
        magic = struct.unpack(">I", data[:4])[0]
        macho_magics = {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA}
        if magic in macho_magics:
            return "MACHO"
    return "UNKNOWN"


def extract_strings(data: bytes, min_length: int = 4) -> str:
    """Extract ASCII and UTF-16LE strings from raw bytes."""
    strings: list[str] = []

    # ASCII
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    for m in re.finditer(pattern, data):
        strings.append(m.group().decode("ascii", errors="ignore"))

    # UTF-16LE
    u_pattern = rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    for m in re.finditer(u_pattern, data):
        try:
            decoded = m.group().decode("utf-16le", errors="ignore")
            if len(decoded) >= min_length:
                strings.append(decoded)
        except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
            pass

    return "\n".join(strings)


def extract_hostnames(text: str) -> list[str]:
    """Extract valid hostnames/domains from *text*."""
    candidates = _HOSTNAME_RE.findall(text)
    valid: list[str] = []
    for hostname in candidates:
        tld = hostname.rsplit(".", 1)[-1].lower()
        if (
            tld in VALID_SUFFIXES
            and len(hostname) > 4
            and not hostname.startswith(("0.", "1."))
        ):
            valid.append(hostname.lower())
    return sorted(set(valid))


@register_plugin
class NetworkGraphPlugin(Plugin):
    """Extract domains/hostnames from binary strings."""

    name = "network_graph"
    stage = Stage.REPORTING
    description = "Domain/hostname extraction and network graph"

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()
        try:
            fmt = _detect_format(file_data)
            if fmt == "UNKNOWN":
                return self._make_result(
                    success=False,
                    error="Unsupported binary format",
                    duration=time.monotonic() - t0,
                )

            strings_data = extract_strings(file_data)
            domains = extract_hostnames(strings_data)

            result: dict[str, Any] = {
                "format": fmt,
                "domains": domains,
                "domain_count": len(domains),
            }

            # Store for the reporter plugin
            context.shared_data["network_graph"] = result

            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Network graph analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
