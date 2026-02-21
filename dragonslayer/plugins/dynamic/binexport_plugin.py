"""
BinExport Protobuf Generator
==============================

Ported from ``repos/stage4/working/binexport/binexport.py``.

Wraps Ghidra headless analysis to produce BinExport2 protobuf files,
which are consumed downstream by the vector_share enrichment plugin.

This plugin requires external tools (Ghidra + BinExport plugin) and
is only useful when those are available.  In standalone mode it can
also load pre-existing ``.BinExport`` files and extract function
metadata.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_BINEXPORT = False
try:
    from binexport import ProgramBinExport  # type: ignore[import-untyped]

    _HAS_BINEXPORT = True
except (ImportError, OSError):
    pass


@register_plugin
class BinExportPlugin(Plugin):
    """Load or generate BinExport protobuf and extract function list."""

    name = "binexport"
    stage = Stage.DYNAMIC
    description = "BinExport2 protobuf function extraction"

    @classmethod
    def available(cls) -> bool:
        return _HAS_BINEXPORT

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        be_path = self._resolve_binexport(file_path, context)
        if not be_path:
            return self._make_result(
                success=False,
                error="No .BinExport file found",
                duration=time.monotonic() - t0,
            )

        try:
            result = self._analyze(be_path)
            context.shared_data["binexport"] = result
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("BinExport analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _resolve_binexport(self, file_path: str, ctx: PluginContext) -> Optional[str]:
        if file_path and file_path.endswith(".BinExport") and os.path.isfile(file_path):
            return file_path
        candidates = []
        if file_path:
            candidates.append(file_path + ".BinExport")
            candidates.append(os.path.splitext(file_path)[0] + ".BinExport")
        if ctx.work_dir:
            for fname in os.listdir(ctx.work_dir):
                if fname.endswith(".BinExport"):
                    candidates.append(os.path.join(ctx.work_dir, fname))
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    def _analyze(self, be_path: str) -> Dict[str, Any]:
        be = ProgramBinExport(be_path)
        functions: list[Dict[str, Any]] = []
        total_instructions = 0
        call_graph_edges: list[tuple[int, int]] = []

        for func_addr, func in be.items():
            mnemonics: list[str] = []
            instructions: list[Dict[str, Any]] = []
            block_count = 0

            # Walk basic blocks → instructions when the API exposes them.
            if hasattr(func, "blocks") or hasattr(func, "__iter__"):
                blocks = func.blocks if hasattr(func, "blocks") else list(func)
                block_count = len(blocks) if blocks else 0
                for bb in (blocks or []):
                    bb_insns = (
                        bb.instructions
                        if hasattr(bb, "instructions")
                        else list(bb) if hasattr(bb, "__iter__") else []
                    )
                    for inst in bb_insns:
                        mnem = getattr(inst, "mnemonic", "")
                        if mnem:
                            mnemonics.append(mnem.lower())
                        inst_entry: Dict[str, Any] = {"mnemonic": mnem.lower()}
                        if hasattr(inst, "address"):
                            inst_entry["address"] = inst.address
                        if hasattr(inst, "operands"):
                            inst_entry["operands"] = [
                                str(o) for o in inst.operands
                            ]
                        instructions.append(inst_entry)

            total_instructions += len(instructions)

            # Cross-references / callees.
            callees: list[int] = []
            if hasattr(func, "callees"):
                callees = [int(c) for c in func.callees]
                for callee in callees:
                    call_graph_edges.append((func_addr, callee))

            func_entry: Dict[str, Any] = {
                "name": func.name,
                "address": func_addr,
                "block_count": block_count,
                "instruction_count": len(instructions),
                "mnemonics": mnemonics,
                "instructions": instructions,
                "callees": callees,
            }
            functions.append(func_entry)

        confidence = min(1.0, len(functions) / 100)
        return {
            "binexport_path": be_path,
            "function_count": len(functions),
            "total_instructions": total_instructions,
            "call_graph_edge_count": len(call_graph_edges),
            "call_graph_edges": call_graph_edges[:500],  # cap for serialisation
            "functions": functions,
            "confidence": round(confidence, 4),
        }
