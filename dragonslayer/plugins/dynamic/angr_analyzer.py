"""
angr CFG + VEX IR analyser
===========================

Ported from ``repos/stage4/working/angr/angr_analyzer.py``.

Builds a control-flow graph with *angr*, extracts per-function VEX IR
mnemonic vectors, and optionally uses Qiling execution-trace guidance
from the shared context to focus analysis on executed regions.

Heavy dependency: ``angr`` (+ ``archinfo``, ``pyvex``, ``cle``).
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_ANGR = False
try:
    import angr  # type: ignore[import-untyped]

    _HAS_ANGR = True
except Exception:
    pass


@register_plugin
class AngrAnalyzer(Plugin):
    """Build CFG and extract VEX-IR feature vectors with *angr*."""

    name = "angr"
    stage = Stage.DYNAMIC
    description = "angr CFG analysis and VEX IR mnemonic extraction"

    @classmethod
    def available(cls) -> bool:
        return _HAS_ANGR

    # ------------------------------------------------------------------ #

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        # If we only have bytes, write to a temp file
        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path, context)
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except Exception as exc:
            logger.exception("angr analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ------------------------------------------------------------------ #

    def _analyze(self, file_path: str, ctx: PluginContext) -> Dict[str, Any]:
        # Load Qiling guidance from shared context (populated by qiling plugin)
        guidance: List[int] = []
        qiling_data = ctx.shared_data.get("qiling", {})
        if isinstance(qiling_data, dict):
            for blk in qiling_data.get("executed_blocks", []):
                addr = blk if isinstance(blk, int) else blk.get("start", 0)
                if addr:
                    guidance.append(addr)

        # Create angr project
        proj = angr.Project(file_path, auto_load_libs=False)

        # Build CFG
        if guidance:
            cfg = proj.analyses.CFGEmulated(
                starts=guidance[:50],
                call_depth=3,
                normalize=True,
            )
        else:
            cfg = proj.analyses.CFGFast(normalize=True)

        functions_data: List[Dict[str, Any]] = []
        total_blocks = 0

        for func_addr, func in cfg.kb.functions.items():
            if func.is_simprocedure or func.is_plt:
                continue

            mnemonic_counter: Counter[str] = Counter()
            block_count = 0

            for block_node in func.blocks:
                block_count += 1
                total_blocks += 1
                try:
                    vex_block = proj.factory.block(block_node.addr).vex
                    for stmt in vex_block.statements:
                        mnemonic_counter[type(stmt).__name__] += 1
                except Exception:
                    continue

            func_hash = hashlib.md5(
                f"{func.name}:{list(mnemonic_counter.items())}".encode()
            ).hexdigest()

            func_entry: Dict[str, Any] = {
                "name": func.name,
                "address": func_addr,
                "block_count": block_count,
                "mnemonics": dict(mnemonic_counter),
                "hash": func_hash,
            }

            # If this function was in the Qiling trace, flag it
            if guidance and func_addr in guidance:
                func_entry["dynamically_reached"] = True

            functions_data.append(func_entry)

        confidence = min(1.0, len(functions_data) / 50) if functions_data else 0.0

        return {
            "arch": str(proj.arch),
            "entry_point": hex(proj.entry),
            "function_count": len(functions_data),
            "total_blocks": total_blocks,
            "functions": functions_data,
            "guidance_addresses": len(guidance),
            "confidence": round(confidence, 4),
        }
