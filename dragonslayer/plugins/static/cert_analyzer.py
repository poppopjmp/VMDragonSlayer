"""
Certificate / Code-Signature Analyser
======================================

Ported from ``repos/stage3/working/cert-analyzer/scan.py``.

Detects PE Authenticode signatures (subject, issuer, serial, validity,
algorithm) and Mach-O code-signature presence using **lief**.

Dependency: ``lief``.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from typing import Any

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_LIEF = False
try:
    import lief
    _HAS_LIEF = True
except ImportError:
    pass


@register_plugin
class CertAnalyzer(Plugin):
    """Detect and extract code-signing certificate information."""

    name = "cert_analyzer"
    stage = Stage.STATIC
    description = "PE Authenticode and Mach-O code-signature detection"

    @classmethod
    def available(cls) -> bool:
        return _HAS_LIEF

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        tmp_path: str | None = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._scan(file_path)
            context.shared_data["cert_analyzer"] = result
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Certificate analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @staticmethod
    def _scan(file_path: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "signed": False,
            "certificates": [],
            "format": "unknown",
        }

        binary = lief.parse(file_path)
        if binary is None:
            result["error"] = "Unknown or unsupported file format"
            return result

        fmt = getattr(binary, "format", None)
        result["format"] = fmt.name if fmt is not None else "unknown"

        # PE Authenticode ---------------------------------------------------
        if isinstance(binary, lief.PE.Binary):
            if len(binary.signatures) > 0:
                result["signed"] = True
                for sig in binary.signatures:
                    for crt in sig.certificates:
                        cert_info: dict[str, str] = {
                            "subject": str(crt.subject),
                            "issuer": str(crt.issuer),
                            "serial": str(crt.serial_number),
                            "valid_from": str(crt.valid_from),
                            "valid_to": str(crt.valid_to),
                            "algorithm": str(crt.signature_algorithm),
                        }
                        result["certificates"].append(cert_info)

        # Mach-O Code Signature ---------------------------------------------
        elif isinstance(binary, lief.MachO.Binary):
            if binary.has_code_signature:
                result["signed"] = True
                result["certificates"].append({
                    "type": "Mach-O Code Signature",
                    "details": "Present (raw CMS blob not parsed further)",
                })

        # ELF - no standard signing mechanism
        elif isinstance(binary, lief.ELF.Binary):
            pass

        return result
