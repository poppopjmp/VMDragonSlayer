"""
Qiling Emulation Plugin
========================

Ported from ``repos/stage4/working/qiling/qiling_analyzer.py``.

Emulates the target binary with the *Qiling* framework, collecting a
block-level execution trace that downstream plugins (angr, triton,
vector_share) use as guidance for focused analysis.

Heavy dependency: ``qiling``.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_QILING = False
try:
    from qiling import Qiling  # type: ignore[import-untyped]
    from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]

    _HAS_QILING = True
except Exception:
    pass


def _detect_rootfs(file_data: bytes, context: PluginContext) -> Optional[str]:
    """
    Heuristic root-FS detection.

    Checks shared_data for fileinfo results, falls back to magic-byte
    detection.  Returns a rootfs path suitable for Qiling or ``None``.
    """
    fileinfo = context.shared_data.get("fileinfo", {})
    file_type = fileinfo.get("type", "").lower()

    # Map file type strings to Qiling rootfs subdirectories
    rootfs_map = {
        "pe32": "x86_windows",
        "pe32+": "x8664_windows",
        "elf 32": "x86_linux",
        "elf 64": "x8664_linux",
        "mach-o 64": "x8664_macos",
    }

    for key, rootfs_name in rootfs_map.items():
        if key in file_type:
            candidate = os.path.join(os.sep, "qiling", "rootfs", rootfs_name)
            if os.path.isdir(candidate):
                return candidate

    # Fallback: magic bytes
    if file_data[:2] == b"MZ":
        for name in ("x86_windows", "x8664_windows"):
            p = os.path.join(os.sep, "qiling", "rootfs", name)
            if os.path.isdir(p):
                return p
    elif file_data[:4] == b"\x7fELF":
        for name in ("x86_linux", "x8664_linux"):
            p = os.path.join(os.sep, "qiling", "rootfs", name)
            if os.path.isdir(p):
                return p

    # User-supplied via config
    return context.config.get("qiling.rootfs")


@register_plugin
class QilingAnalyzer(Plugin):
    """Block-level execution trace via Qiling emulation."""

    name = "qiling"
    stage = Stage.DYNAMIC
    description = "Qiling emulation engine — block execution trace"

    @classmethod
    def available(cls) -> bool:
        return _HAS_QILING

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path, file_data, context)
            # Store trace in shared_data for downstream plugins
            context.shared_data["qiling"] = result
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except Exception as exc:
            logger.exception("Qiling analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _analyze(
        self,
        file_path: str,
        file_data: bytes,
        ctx: PluginContext,
    ) -> Dict[str, Any]:
        rootfs = _detect_rootfs(file_data, ctx)
        if not rootfs:
            raise FileNotFoundError(
                "Qiling rootfs not found — set config 'qiling.rootfs' or "
                "install rootfs at /qiling/rootfs/<arch>_<os>"
            )

        executed_blocks: List[Dict[str, int]] = []
        block_set: set[int] = set()
        max_blocks = int(ctx.config.get("qiling.max_blocks", 50_000))

        def _block_hook(ql: Any, address: int, size: int) -> None:
            if len(block_set) >= max_blocks:
                ql.stop()
                return
            if address not in block_set:
                block_set.add(address)
                executed_blocks.append({"start": address, "end": address + size})

        timeout = int(ctx.config.get("qiling.timeout", 60))

        ql = Qiling(
            [file_path],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
        ql.hook_block(_block_hook)

        try:
            ql.run(timeout=timeout * 1_000_000)  # microseconds
        except Exception as exc:
            logger.warning("Qiling run ended with: %s", exc)

        confidence = min(1.0, len(executed_blocks) / 1000)

        return {
            "rootfs": rootfs,
            "executed_blocks": executed_blocks,
            "unique_blocks": len(block_set),
            "confidence": round(confidence, 4),
        }
