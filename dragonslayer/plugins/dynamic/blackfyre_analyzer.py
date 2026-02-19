"""
Blackfyre BCC Function Analyser
================================

Ported from ``repos/stage4/working/blackfyre/blackfyre.py``.

Processes Blackfyre BCC (Binary Code Context) files — typically
produced by a Ghidra headless export — extracting per-function
metadata, computing function hashes, and storing results in the
shared context / storage backend so the enrichment plugins
(similarity, vector_share) can match functions across samples.

Heavy dependency: ``blackfyre``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_BLACKFYRE = False
try:
    from blackfyre.datatypes.contexts.binarycontext import BinaryContext  # type: ignore[import-untyped]

    _HAS_BLACKFYRE = True
except Exception:
    pass


def _function_hash(name: str, mnemonics: List[str]) -> str:
    """Stable hash for a function based on its mnemonic sequence."""
    payload = f"{name}:{','.join(mnemonics)}"
    return hashlib.md5(payload.encode()).hexdigest()


@register_plugin
class BlackfyreAnalyzer(Plugin):
    """Parse Blackfyre BCC exports and build a function database."""

    name = "blackfyre"
    stage = Stage.DYNAMIC
    description = "Blackfyre BCC function extraction and hashing"

    @classmethod
    def available(cls) -> bool:
        return _HAS_BLACKFYRE

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        # Blackfyre works on .bcc files, not raw binaries
        # Accept either the binary (to check if a .bcc sibling exists)
        # or a .bcc file directly
        bcc_path = self._resolve_bcc_path(file_path, context)
        if not bcc_path:
            return self._make_result(
                success=False,
                error="No .bcc file found for analysis",
                duration=time.monotonic() - t0,
            )

        try:
            result = self._analyze(bcc_path, context)
            context.shared_data["blackfyre"] = result
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except Exception as exc:
            logger.exception("Blackfyre analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _resolve_bcc_path(self, file_path: str, ctx: PluginContext) -> Optional[str]:
        """Check for a .bcc file adjacent to the sample, or if file_path itself is one."""
        if file_path and file_path.endswith(".bcc") and os.path.isfile(file_path):
            return file_path

        # Check work_dir or sibling paths
        candidates = []
        if file_path:
            base = os.path.splitext(file_path)[0]
            candidates.append(base + ".bcc")
            candidates.append(file_path + ".bcc")
        if ctx.work_dir:
            for fname in os.listdir(ctx.work_dir):
                if fname.endswith(".bcc"):
                    candidates.append(os.path.join(ctx.work_dir, fname))

        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    def _analyze(self, bcc_path: str, ctx: PluginContext) -> Dict[str, Any]:
        bcc = BinaryContext.load_from_file(bcc_path)

        functions: List[Dict[str, Any]] = []

        func_contexts = list(bcc.function_contexts) if hasattr(bcc, "function_contexts") else []

        for func in func_contexts:
            mnemonics: List[str] = []
            block_count = 0

            if hasattr(func, "basic_block_context_dict") and isinstance(
                func.basic_block_context_dict, dict
            ):
                block_count = len(func.basic_block_context_dict)
                for _bb_addr, bb in sorted(func.basic_block_context_dict.items()):
                    if hasattr(bb, "instruction_contexts"):
                        for inst in bb.instruction_contexts:
                            if hasattr(inst, "mnemonic"):
                                mnemonics.append(inst.mnemonic.lower())

            fhash = _function_hash(func.name, mnemonics)

            func_entry: Dict[str, Any] = {
                "name": func.name,
                "address": func.address,
                "block_count": block_count,
                "instruction_count": len(mnemonics),
                "hash": fhash,
            }
            functions.append(func_entry)

            # Store in storage backend for cross-sample look-ups
            if ctx.storage and func.name and not func.name.startswith(("sub_", "FUN_")):
                ctx.storage.store(
                    "blackfyre_functions",
                    fhash,
                    {
                        "name": func.name,
                        "address": func.address,
                        "sample": ctx.sample_hash,
                        "hash": fhash,
                    },
                )

        confidence = min(1.0, len(functions) / 100) if functions else 0.0

        return {
            "bcc_path": bcc_path,
            "function_count": len(functions),
            "functions": functions,
            "confidence": round(confidence, 4),
        }
