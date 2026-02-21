"""
FrankenStrings — Advanced String Extraction & IOC Detection
============================================================

Ported from ``repos/stage3/working/frankenstrings/frankenstrings.py``.

Features
--------
* ASCII / Unicode string extraction with IOC pattern matching
* Base64 decoding & embedded file extraction
* Embedded PE detection
* Unicode-encoded string decoding (``\\u``, ``%u``, ``\\x``, ``0x``, ``&H``)
* ASCII-HEX decoding
* XOR obfuscation detection (optional — requires *bbcrack*)

Optional heavy deps: ``multidecoder``, ``assemblyline-service-utilities``.
None are required — the plugin degrades gracefully.
"""

from __future__ import annotations

import binascii
import hashlib
import logging
import os
import re
import tempfile
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

# Optional heavyweight dependencies -------------------------------------------
_HAS_MULTIDECODER = False
try:
    from multidecoder.multidecoder import Multidecoder   # type: ignore[import-untyped]
    from multidecoder.decoders.codec import find_utf16    # type: ignore[import-untyped]
    from multidecoder.decoders.pe_file import find_pe_files  # type: ignore[import-untyped]
    from multidecoder.registry import build_registry       # type: ignore[import-untyped]
    _HAS_MULTIDECODER = True
except ImportError:
    pass

_HAS_BBCRACK = False
try:
    from assemblyline_service_utilities.common.balbuzard.bbcrack import bbcrack  # type: ignore[import-untyped]
    _HAS_BBCRACK = True
except ImportError:
    pass

# Constants -------------------------------------------------------------------
MAX_STRING_LENGTH = 1_000
MIN_STRING_LENGTH = 7
BASE64_RE = rb"={0,2}(?:[A-Za-z0-9+/]{10,}(?:&#(?:x[AD]|1[03]);)?[\r]?[\n]?){2,}[A-Za-z0-9+/]{2,}={0,2}"
PAT_EXEHEADER = rb"(?s)MZ.{32,1024}PE\000\000.+"
PAT_EXEDOS = rb"(?s)This program cannot be run in DOS mode"

IOC_PATTERNS: Dict[str, bytes] = {
    "ip":         rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "url":        rb"https?://[^\s<>\"']+",
    "domain":     rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    "email":      rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "registry_key": rb"(?:HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*)",
    "file_path":  rb"(?:[a-zA-Z]:\\\\(?:[^\\/:*?\"<>|\r\n]+\\\\)*[^\\/:*?\"<>|\r\n]*)",
    "powershell": rb"(?i)(?:powershell|pwsh|invoke-|iex|downloadstring)",
    "crypto":     rb"(?i)(?:aes|rsa|sha256|md5|base64)",
}

HEXENC_STRINGS = [b"\\u", b"%u", b"\\x", b"0x", b"&H"]


# ---------------------------------------------------------------------------
# Internal analyser (kept as class so state is isolated per run)
# ---------------------------------------------------------------------------

class _FrankenStringsEngine:
    """Stateful helper — one instance per ``execute()`` call."""

    def __init__(self) -> None:
        self.strings: Dict[str, List[Any]] = {
            "ascii": [], "unicode": [], "base64": [],
        }
        self.iocs: Dict[str, List[str]] = defaultdict(list)
        self.embedded_pe: List[Dict[str, Any]] = []
        self.xor_strings: List[Dict[str, Any]] = []
        self.hex_decoded: List[Dict[str, Any]] = []
        self.md: Any = None  # Multidecoder instance (if available)
        if _HAS_MULTIDECODER:
            self.md = Multidecoder(
                decoders=build_registry(include=["codec", "filename", "network", "path"]),
            )

    # ----- public entry point ----
    def analyze(self, data: bytes) -> Dict[str, Any]:
        meta = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "format": self._detect_format(data),
        }

        self._extract_ascii_strings(data)
        self._extract_base64(data)
        self._extract_embedded_pe(data)
        self._extract_unicode_encoded(data)
        self._extract_ascii_hex(data)
        if _HAS_BBCRACK:
            self._extract_xor_strings(data)

        stats = {
            "ascii_strings": len(self.strings["ascii"]),
            "unicode_strings": len(self.strings["unicode"]),
            "base64_decoded": len(self.strings["base64"]),
            "embedded_pe": len(self.embedded_pe),
            "xor_decoded": len(self.xor_strings),
            "hex_decoded": len(self.hex_decoded),
            "total_iocs": sum(len(v) for v in self.iocs.values()),
        }

        return {
            "valid": True,
            "metadata": meta,
            "statistics": stats,
            "iocs": dict(self.iocs),
            "strings": {
                "ascii": self.strings["ascii"][:100],
                "unicode": self.strings["unicode"][:100],
                "base64": self.strings["base64"][:50],
            },
            "embedded_pe": self.embedded_pe,
            "xor_strings": self.xor_strings[:50],
            "hex_decoded": self.hex_decoded[:50],
        }

    # ----- helpers ----

    @staticmethod
    def _detect_format(data: bytes) -> str:
        if data[:2] == b"MZ":
            return "PE"
        if data[:4] == b"\x7fELF":
            return "ELF"
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            return "MACHO"
        if data[:4] == b"%PDF":
            return "PDF"
        if data[:6] in (b"\xd0\xcf\x11\xe0\xa1\xb1", b"\x50\x4b\x03\x04\x00\x00"):
            return "Office/Archive"
        return "Unknown"

    def _check_iocs(self, data: bytes) -> None:
        for ioc_type, pattern in IOC_PATTERNS.items():
            for m in re.finditer(pattern, data, re.IGNORECASE):
                decoded = m.group().decode("ascii", errors="ignore")
                if decoded not in self.iocs[ioc_type]:
                    self.iocs[ioc_type].append(decoded)

    # ---- extractors ----

    def _extract_ascii_strings(self, data: bytes) -> None:
        pat = rb"[\x20-\x7e]{" + str(MIN_STRING_LENGTH).encode() + rb",}"
        for m in re.finditer(pat, data):
            s = m.group()
            if len(s) <= MAX_STRING_LENGTH:
                self.strings["ascii"].append(s.decode("ascii", errors="ignore"))
                self._check_iocs(s)

        if _HAS_MULTIDECODER and self.md:
            try:
                for node in find_utf16(data):
                    val = node.value
                    if MIN_STRING_LENGTH < len(val) <= MAX_STRING_LENGTH:
                        self.strings["unicode"].append(val.decode("utf-16le", errors="ignore"))
                        self._check_iocs(val)
            except (ValueError, TypeError, UnicodeDecodeError, AttributeError):  # noqa: BLE001
                pass

    def _extract_base64(self, data: bytes) -> None:
        findings: List[Dict[str, Any]] = []
        for m in re.finditer(BASE64_RE, data):
            b64 = m.group().replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
            if len(b64) < 16 or len(b64) % 4 != 0:
                continue
            try:
                decoded = binascii.a2b_base64(b64)
            except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
                continue
            h = hashlib.sha256(decoded).hexdigest()

            if len(decoded) > 200 and re.match(PAT_EXEHEADER, decoded) and re.search(PAT_EXEDOS, decoded):
                findings.append({"type": "embedded_exe", "size": len(decoded),
                                 "hash": h, "encoded_snippet": b64[:50].decode("ascii", errors="ignore")})
                continue

            ioc_found = any(re.search(p, decoded, re.IGNORECASE) for p in IOC_PATTERNS.values())
            printable = bytes(i for i in decoded if 31 < i < 127)
            if len(printable) > 20:
                findings.append({
                    "type": "decoded_string", "size": len(decoded), "hash": h,
                    "decoded_preview": printable[:200].decode("ascii", errors="ignore"),
                    "has_iocs": ioc_found,
                })
                self._check_iocs(decoded)

        self.strings["base64"] = findings

    def _extract_embedded_pe(self, data: bytes) -> None:
        if not _HAS_MULTIDECODER:
            return
        try:
            for hit in find_pe_files(data[1:]):
                self.embedded_pe.append({
                    "offset": hit.start + 1, "size": len(hit.value),
                    "hash": hashlib.sha256(hit.value).hexdigest(), "type": "forward",
                })
            for hit in find_pe_files(data[::-1]):
                self.embedded_pe.append({
                    "offset": len(data) - hit.start - len(hit.value),
                    "size": len(hit.value),
                    "hash": hashlib.sha256(hit.value).hexdigest(), "type": "reversed",
                })
        except (ValueError, TypeError, UnicodeDecodeError, AttributeError):  # noqa: BLE001
            pass

    def _extract_unicode_encoded(self, data: bytes) -> None:
        results: List[Dict[str, Any]] = []
        for enc in HEXENC_STRINGS:
            if enc in (b"\\u", b"%u"):
                pat = re.compile(rb"(?:" + re.escape(enc) + b"[A-Fa-f0-9]{4})+")
            else:
                pat = re.compile(rb"(?:" + re.escape(enc) + b"[A-Fa-f0-9]{2})+")
            for m in re.finditer(pat, data):
                try:
                    decoded = self._decode_enc(m.group(), enc)
                    if decoded and len(decoded) > 10:
                        results.append({
                            "encoding": enc.decode("ascii", errors="ignore"),
                            "encoded": m.group()[:50].decode("ascii", errors="ignore"),
                            "decoded": decoded[:200],
                            "size": len(decoded),
                        })
                        self._check_iocs(decoded.encode("utf-8", errors="ignore"))
                except (ValueError, TypeError, UnicodeDecodeError, AttributeError):  # noqa: BLE001
                    continue
        if results:
            self.strings["unicode_encoded"] = results  # type: ignore[assignment]

    @staticmethod
    def _decode_enc(data: bytes, enc: bytes) -> Optional[str]:
        try:
            if enc in (b"\\u", b"%u"):
                parts = data.split(enc)[1:]
                return "".join(chr(int(p[:4], 16)) for p in parts if len(p) >= 4)
            # \\x, 0x, &H
            parts = data.split(enc)[1:]
            raw = b"".join(bytes([int(p[:2], 16)]) for p in parts if len(p) >= 2)
            return raw.decode("utf-8", errors="ignore")
        except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
            return None

    def _extract_ascii_hex(self, data: bytes) -> None:
        results: List[Dict[str, Any]] = []
        for m in re.finditer(rb"[A-Fa-f0-9]{100,}", data):
            chunk = m.group()
            if len(chunk) % 2:
                chunk = chunk[:-1]
            try:
                decoded = binascii.unhexlify(chunk)
            except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
                continue
            if len(set(decoded)) < 7:
                continue
            h = hashlib.sha256(decoded).hexdigest()
            ioc_found = any(re.search(p, decoded, re.IGNORECASE) for p in IOC_PATTERNS.values())
            if ioc_found:
                self._check_iocs(decoded)
            if len(decoded) > 50 or ioc_found:
                printable = bytes(i for i in decoded if 31 < i < 127)
                results.append({
                    "size": len(decoded), "hash": h,
                    "preview": printable[:200].decode("ascii", errors="ignore"),
                    "has_iocs": ioc_found,
                })
        if results:
            self.hex_decoded = results

    def _extract_xor_strings(self, data: bytes) -> None:
        try:
            hits = bbcrack(data[:1_000_000], level=1)
            for transform, regex, offset, score, match in hits:
                self.xor_strings.append({
                    "transform": str(transform), "offset": offset,
                    "score": score, "match_type": regex,
                    "decoded": match[:200].decode("ascii", errors="ignore"),
                })
                self._check_iocs(match)
        except (ValueError, TypeError, UnicodeDecodeError, AttributeError):  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Plugin wrapper
# ---------------------------------------------------------------------------

@register_plugin
class FrankenStrings(Plugin):
    """Advanced string extraction & IOC detection from arbitrary binaries."""

    name = "frankenstrings"
    stage = Stage.STATIC
    description = "String extraction, Base64/XOR decoding, IOC detection"

    @classmethod
    def available(cls) -> bool:
        # The core algorithm uses only stdlib — always available.
        return True

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        if not file_data:
            return self._make_result(success=False, error="Empty file",
                                     duration=time.monotonic() - t0)

        try:
            engine = _FrankenStringsEngine()
            result = engine.analyze(file_data)
            context.shared_data["frankenstrings"] = result
            return self._make_result(
                success=result.get("valid", False),
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("FrankenStrings analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
